package diag

import (
	"context"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

// Verdicts (§13.4). They are stable strings: the frontend renders a different
// explanation and a different suggested fix for each.
const (
	VerdictInterfaceMissing    = "INTERFACE_MISSING"
	VerdictInterfaceDown       = "INTERFACE_DOWN"
	VerdictUnderlayUnreachable = "UNDERLAY_UNREACHABLE"
	VerdictNoReturnTraffic     = "NO_RETURN_TRAFFIC"
	VerdictKeyOrAddressing     = "KEY_OR_ADDRESSING_MISMATCH"
	VerdictMtuProblem          = "MTU_PROBLEM"
	VerdictLocalFirewall       = "LOCAL_FIREWALL_BLOCK"
	// VerdictConfigMismatch means the kernel's live state disagrees with the
	// database record: the interface the panel thinks it manages is not the
	// interface the kernel has. This is the vote the verification casts, and
	// it is the one the Rahyaab stale-rule incidents taught us to name
	// explicitly rather than letting it hide behind "the tunnel is down".
	VerdictConfigMismatch = "CONFIG_MISMATCH"
	VerdictHealthy        = "HEALTHY"
)

// Confidence qualifies a verdict.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// Evidence is one thing the analysis observed. Every verdict carries the
// evidence it rests on: a bare status word is what the script this panel
// replaces offered, and it told an operator nothing (§13.4).
type Evidence struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Data   any    `json:"data,omitempty"`
}

// AnalyzeParams tunes the analysis.
type AnalyzeParams struct {
	// SampleSeconds is how long the counters are watched for movement.
	SampleSeconds float64 `json:"sample_seconds,omitempty"`
	// Capture allows a brief tcpdump when the setting permits it.
	Capture bool `json:"capture,omitempty"`
}

// AnalyzeResult is a specific verdict with its evidence and a suggested fix.
type AnalyzeResult struct {
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	Summary    string `json:"summary"`
	// SuggestedFix is what to do about it, in the order worth trying.
	SuggestedFix []string `json:"suggested_fix,omitempty"`
	// Votes is how the verdict was reached: every signal that cast a vote,
	// the cause it voted for, and its weight. A bare verdict told an
	// operator nothing about why the panel thinks what it thinks; the votes
	// are the reasoning, and they are what makes a wrong verdict checkable
	// rather than merely disagreeable.
	Votes     []Vote     `json:"votes,omitempty"`
	Evidence  []Evidence `json:"evidence"`
	CheckedAt string     `json:"checked_at"`
}

// Vote is one signal's say in the verdict: the cause it votes for, why, and
// how much its say counts. The verdict is the cause with the highest total
// weight; ties break by the priority order in verdictPriority.
type Vote struct {
	Signal string `json:"signal"`
	Cause  string `json:"cause"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

func (r *AnalyzeResult) add(name, detail string, data any) {
	r.Evidence = append(r.Evidence, Evidence{Name: name, Detail: detail, Data: data})
}

// Analyze runs the decision tree and returns a specific verdict (§13.4).
func (s *Service) Analyze(ctx context.Context, tunnelID int64, params AnalyzeParams) (Run, AnalyzeResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, AnalyzeResult{}, err
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypeAnalyze, params)
	if err != nil {
		return Run{}, AnalyzeResult{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	result := s.analyze(runCtx, rec, params)
	result.CheckedAt = model.NowUTC()

	if err := s.finish(ctx, runID, result, true); err != nil {
		s.log.Error("recording an analysis result failed", "run_id", runID, "error", err)
	}
	release()
	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypeAnalyze,
		Type: TypeName(model.DiagnosticTypeAnalyze), Params: params, Result: result, IsSuccess: true,
	})
	return run, result, nil
}

// analyze is the decision tree itself, in the order of §13.4.
func (s *Service) analyze(ctx context.Context, rec tunnel.Record, params AnalyzeParams) AnalyzeResult {
	result := AnalyzeResult{Confidence: ConfidenceHigh, Evidence: []Evidence{}}
	name := rec.InterfaceName

	// 1. The interface has to exist.
	observed, err := s.links.Get(ctx, name)
	if err != nil {
		result.Verdict = VerdictInterfaceMissing
		result.Summary = i18n.T(ctx, "There is no interface called %s on this host.", name)
		result.add("interface", i18n.T(ctx, "the interface was not found"),
			map[string]any{"interface_name": name})
		result.SuggestedFix = []string{
			i18n.T(ctx, "Reapply this tunnel, which rebuilds it from the stored configuration."),
			i18n.T(ctx, "Check whether something outside the panel removed it."),
		}
		return result
	}
	result.add("interface", i18n.T(ctx, "%s exists as a %s interface with an MTU of %d",
		name, observed.Kind, observed.MTU),
		map[string]any{"kind": observed.Kind, "mtu": observed.MTU, "oper_state": observed.OperState})

	// 2. It has to be up. Health comes from the flags: a working GRE tunnel
	// reports operational state UNKNOWN, so that field is reported and never
	// used to decide (§2).
	if !observed.IsUp || !observed.IsLowerUp {
		result.Verdict = VerdictInterfaceDown
		result.Summary = i18n.T(ctx, "%s exists but is not up: its flags are %s.",
			name, strings.Join(observed.Flags, ","))
		result.add("flags", i18n.T(ctx, "the interface is missing UP or LOWER_UP"),
			map[string]any{"flags": observed.Flags, "oper_state": observed.OperState})
		result.SuggestedFix = []string{
			i18n.T(ctx, "Bring the tunnel up from the panel."),
			i18n.T(ctx, "Reapply it if bringing it up does not work."),
		}
		return result
	}
	result.add("flags", i18n.T(ctx, "the flags are %s and the operational state is %s, which is normal "+
		"for a point-to-point tunnel", strings.Join(observed.Flags, ","), observed.OperState), nil)

	source, target := probeEndpoints(rec)

	// 3. The underlay has to carry packets, though ICMP being filtered while
	// GRE works is common enough that this is never a confident verdict.
	underlayReachable := false
	if rec.RemoteEndpoint != "" && rec.LocalEndpoint != "" {
		reply, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
			TunnelID: rec.TunnelID, Source: rec.LocalEndpoint, Target: rec.RemoteEndpoint,
			Count: 3, Interval: 200 * time.Millisecond, Timeout: time.Second,
		}, nil)
		switch {
		case err != nil:
			result.add("underlay", i18n.T(ctx, "the underlay could not be probed: %v", err), nil)
		case reply.Received > 0:
			underlayReachable = true
			result.add("underlay", i18n.T(ctx, "%d of %d probes to the remote endpoint %s were answered",
				reply.Received, reply.Sent, rec.RemoteEndpoint), reply)
		default:
			result.add("underlay", i18n.T(ctx, "none of the %d probes to the remote endpoint %s were answered",
				reply.Sent, rec.RemoteEndpoint), reply)
		}
	}

	// 4 and 5. Which way traffic is moving is what separates "nothing is coming
	// back" from "something is coming back but it is not usable".
	before, after, elapsed := s.watchCounters(ctx, name, params.SampleSeconds)
	txMoved := after.TxBytes > before.TxBytes
	rxMoved := after.RxBytes > before.RxBytes
	result.add("counters", i18n.T(ctx,
		"over %.1f s the interface sent %d bytes and received %d bytes",
		elapsed, after.TxBytes-before.TxBytes, saturating(after.RxBytes, before.RxBytes)),
		map[string]any{
			"tx_bytes_delta": after.TxBytes - before.TxBytes,
			"rx_bytes_delta": saturating(after.RxBytes, before.RxBytes),
			"seconds":        elapsed,
		})

	// The probe through the tunnel is what says whether it actually works.
	tunnelReachable := false
	var tunnelLoss float64 = 100
	if source != "" && target != "" {
		reply, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
			TunnelID: rec.TunnelID, Source: source, Target: target,
			Count: 5, Interval: 200 * time.Millisecond, Timeout: time.Second,
		}, nil)
		if err != nil {
			result.add("tunnel_probe", i18n.T(ctx, "the tunnel could not be probed: %v", err), nil)
		} else {
			tunnelReachable = reply.Received > 0
			tunnelLoss = reply.LossPercent
			result.add("tunnel_probe", i18n.T(ctx, "%d of %d probes through the tunnel were answered",
				reply.Received, reply.Sent), reply)
		}
	} else {
		result.add("tunnel_probe", i18n.T(ctx, "this tunnel has no address pair, so it cannot be probed "+
			"end to end"), nil)
	}

	firewall := s.inspectFirewall(ctx)
	if firewall != nil {
		result.Evidence = append(result.Evidence, *firewall)
	}
	if capture := s.capture(ctx, params, observed, rec); capture != nil {
		result.Evidence = append(result.Evidence, *capture)
	}

	// The verdict is a vote, not the first failure. Each signal that measured
	// something casts a vote for the cause it points at, with a weight for how
	// much its say counts, and the cause with the highest total weight wins.
	// A decision tree stops at the first failure and never learns that a
	// second signal disagrees; a vote shows the disagreement, and the votes
	// are returned so the operator can see the reasoning and check it.
	// The kernel-versus-database check votes too: a live interface that does
	// not match the stored record is a configuration mismatch, not a broken
	// tunnel, and naming it explicitly is what stops the next stale-rule
	// incident from being misread as a path failure.
	var votes []Vote
	vote := func(signal, cause string, weight int, detail string) {
		votes = append(votes, Vote{Signal: signal, Cause: cause, Weight: weight, Detail: detail})
	}

	// The verification voter: the kernel's live state against the database.
	mismatch := ""
	if s.verify != nil {
		report := s.verify.Verify(ctx, rec)
		if !report.Ok {
			failures := report.Failures
			mismatch = strings.Join(failures, "; ")
			result.add("kernel_vs_database", i18n.T(ctx,
				"the live state does not match the stored record: %s", mismatch),
				map[string]any{"failures": failures})
		} else {
			result.add("kernel_vs_database", i18n.T(ctx,
				"the live state matches the stored record"), nil)
		}
	}
	if mismatch != "" {
		vote("kernel_vs_database", VerdictConfigMismatch, 6, mismatch)
	}

	// A local rule that blocks protocol 47 explains everything above it, so
	// it votes heavily.
	firewallBlocks := false
	if firewall != nil && firewall.Data != nil {
		if blocked, ok := firewall.Data.(map[string]any)["blocks_gre"].(bool); ok && blocked {
			firewallBlocks = true
			vote("firewall", VerdictLocalFirewall, 8,
				i18n.T(ctx, "A firewall rule on this host affects protocol 47, which is what GRE uses."))
		}
	}

	// The tunnel works and the record matches: nothing votes against it.
	if tunnelReachable && tunnelLoss == 0 && mismatch == "" && !firewallBlocks {
		result.Verdict = VerdictHealthy
		result.Summary = i18n.T(ctx, "%s is up and carrying traffic: every probe through it was answered.", name)
		return result
	}

	// Which way traffic is moving is what separates "nothing is coming back"
	// from "something is coming back but it is not usable".
	if txMoved && !rxMoved {
		vote("counters", VerdictNoReturnTraffic, 5,
			i18n.T(ctx, "%s is sending but nothing is coming back.", name))
	}
	if rxMoved && !tunnelReachable {
		vote("counters", VerdictKeyOrAddressing, 5,
			i18n.T(ctx, "%s is receiving traffic, but probes through it are not being answered.", name))
	}
	if !underlayReachable && !txMoved && !rxMoved {
		vote("underlay", VerdictUnderlayUnreachable, 5,
			i18n.T(ctx, "The remote endpoint %s did not answer, so the two servers may not be able to reach each other at all.", rec.RemoteEndpoint))
	}

	// Small packets get through and large ones do not.
	mtuBroken := false
	if tunnelReachable {
		if mtu := s.probeMtuShape(ctx, rec, source, target); mtu != nil {
			result.Evidence = append(result.Evidence, *mtu)
			if broken, ok := mtu.Data.(map[string]any)["large_packets_fail"].(bool); ok && broken {
				mtuBroken = true
				vote("mtu", VerdictMtuProblem, 4,
					i18n.T(ctx, "%s answers small packets but not large ones, which is an MTU problem.", name))
			}
		}
	}
	_ = mtuBroken

	// A tunnel that answers but loses probes is healthy with a warning, not
	// broken: the loss votes for Healthy, weakly, so a stronger failure
	// signal still wins.
	if tunnelReachable && tunnelLoss > 0 {
		vote("tunnel_probe", VerdictHealthy, 2,
			i18n.T(ctx, "%s is answering but losing %.0f%% of probes.", name, tunnelLoss))
	}

	if len(votes) == 0 {
		// Nothing measured a failure and the tunnel does not answer cleanly:
		// the remote endpoint answers, but the tunnel carries nothing in
		// either direction.
		vote("counters", VerdictNoReturnTraffic, 5,
			i18n.T(ctx, "The remote endpoint answers, but %s is not carrying traffic in either direction.", name))
	}

	result.Votes = votes
	winner := winningVerdict(votes)
	result.Verdict = winner
	result.Summary, result.SuggestedFix = verdictSummary(ctx, winner, name, rec, tunnelLoss)
	if winner == VerdictHealthy {
		result.Confidence = ConfidenceLow
	}
	return result
}

// verdictPriority breaks ties between causes with the same total weight: the
// more specific and the more local the cause, the earlier it wins.
var verdictPriority = []string{
	VerdictInterfaceMissing,
	VerdictInterfaceDown,
	VerdictLocalFirewall,
	VerdictConfigMismatch,
	VerdictNoReturnTraffic,
	VerdictKeyOrAddressing,
	VerdictUnderlayUnreachable,
	VerdictMtuProblem,
	VerdictHealthy,
}

// winningVerdict returns the cause with the highest total vote weight,
// breaking ties by verdictPriority.
func winningVerdict(votes []Vote) string {
	totals := map[string]int{}
	for _, v := range votes {
		totals[v.Cause] += v.Weight
	}
	best := ""
	bestWeight := -1
	for _, cause := range verdictPriority {
		if totals[cause] > bestWeight {
			best, bestWeight = cause, totals[cause]
		}
	}
	if best == "" && len(votes) > 0 {
		best = votes[0].Cause
	}
	return best
}

// verdictSummary renders the summary and the suggested fix for a winning
// cause.
func verdictSummary(ctx context.Context, verdict, name string, rec tunnel.Record, tunnelLoss float64) (string, []string) {
	switch verdict {
	case VerdictLocalFirewall:
		return i18n.T(ctx, "A firewall rule on this host affects protocol 47, which is what GRE uses."),
			[]string{i18n.T(ctx, "Review the rule the evidence quotes and allow protocol 47 to and from the remote endpoint.")}
	case VerdictConfigMismatch:
		return i18n.T(ctx, "The live state of %s does not match the stored record, so the panel is managing a tunnel the kernel does not have.",
				name),
			[]string{
				i18n.T(ctx, "Reapply this tunnel, which rebuilds the live state from the stored record."),
				i18n.T(ctx, "Check whether something outside the panel changed the interface or its unit."),
			}
	case VerdictNoReturnTraffic:
		return i18n.T(ctx, "%s is sending but nothing is coming back.", name),
			[]string{
				i18n.T(ctx, "Protocol 47 may be filtered by a provider or a firewall between the two servers."),
				i18n.T(ctx, "Protocol 47 may be filtered even though ICMP is not."),
				i18n.T(ctx, "The other end may not be configured yet; check that its tunnel exists and is up."),
				i18n.T(ctx, "Check that the other end's tunnel exists, is up, and points back at this server."),
				i18n.T(ctx, "The remote endpoint may be wrong: this tunnel points at %s.", rec.RemoteEndpoint),
			}
	case VerdictKeyOrAddressing:
		return i18n.T(ctx, "%s is receiving traffic, but probes through it are not being answered.", name),
			[]string{
				i18n.T(ctx, "Check that the GRE keys match exactly on both servers; a mismatch makes the kernel drop the packets."),
				i18n.T(ctx, "Check that the peer address %s is inside this tunnel's own subnet.", probeTarget(rec)),
				i18n.T(ctx, "Check that the MTU, the checksum flags and the sequence flags match on both ends."),
			}
	case VerdictUnderlayUnreachable:
		return i18n.T(ctx, "The remote endpoint %s did not answer, so the two servers may not be able to reach each other at all.",
				rec.RemoteEndpoint),
			[]string{
				i18n.T(ctx, "Check that the remote endpoint address is right."),
				i18n.T(ctx, "ICMP is often filtered while GRE still works, so confirm this before acting on it."),
				i18n.T(ctx, "Check that the other end is up and reachable by some other means."),
			}
	case VerdictMtuProblem:
		return i18n.T(ctx, "%s answers small packets but not large ones, which is an MTU problem.", name),
			[]string{
				i18n.T(ctx, "Run the path MTU probe and apply the tunnel MTU it recommends."),
				i18n.T(ctx, "Set the same MTU on both ends: they have to agree."),
			}
	case VerdictHealthy:
		return i18n.T(ctx, "%s is up and answering, with %.0f%% of probes lost.", name, tunnelLoss),
			[]string{i18n.T(ctx, "Watch the monitoring history: intermittent loss is usually the path rather than the tunnel.")}
	default:
		return i18n.T(ctx, "%s is not carrying traffic.", name),
			[]string{i18n.T(ctx, "Reapply this tunnel, which rebuilds it from the stored configuration.")}
	}
}

// probeTarget returns the peer address the tunnel probe uses, for the
// key-or-addressing fix.
func probeTarget(rec tunnel.Record) string {
	_, target := probeEndpoints(rec)
	return target
}

// watchCounters reads the interface counters twice, so which way traffic is
// moving can be told from whether they moved at all.
func (s *Service) watchCounters(ctx context.Context, name string, sampleSeconds float64) (before, after link.Statistics, elapsed float64) {
	if sampleSeconds <= 0 {
		sampleSeconds = 2
	}
	if sampleSeconds > 30 {
		sampleSeconds = 30
	}

	before, _ = s.links.Statistics(ctx, name)
	started := time.Now()

	timer := time.NewTimer(time.Duration(sampleSeconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}

	after, _ = s.links.Statistics(ctx, name)
	return before, after, time.Since(started).Seconds()
}

// probeMtuShape checks whether large packets fail while small ones succeed,
// which is the shape of an MTU problem rather than a reachability one.
func (s *Service) probeMtuShape(ctx context.Context, rec tunnel.Record, source, target string) *Evidence {
	if source == "" || target == "" {
		return nil
	}
	large := int(rec.Mtu) - icmpEchoOverhead
	if large < monitor.MinPacketSize+64 {
		return nil
	}

	small, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
		TunnelID: rec.TunnelID, Source: source, Target: target,
		Count: 2, Interval: 100 * time.Millisecond, Timeout: time.Second, PacketSize: monitor.MinPacketSize,
	}, nil)
	if err != nil {
		return nil
	}
	big, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
		TunnelID: rec.TunnelID, Source: source, Target: target,
		Count: 2, Interval: 100 * time.Millisecond, Timeout: time.Second, PacketSize: large,
	}, nil)
	if err != nil {
		return nil
	}

	broken := small.Received > 0 && big.Received == 0
	return &Evidence{
		Name: "packet_size",
		Detail: i18n.T(ctx, "small packets: %d of %d answered; packets filling the %d-byte MTU: %d of %d "+
			"answered", small.Received, small.Sent, rec.Mtu, big.Received, big.Sent),
		Data: map[string]any{
			"large_packets_fail": broken,
			"small_received":     small.Received,
			"large_received":     big.Received,
			"large_payload":      large,
		},
	}
}

// inspectFirewall looks for a local rule affecting protocol 47 (§13.4).
func (s *Service) inspectFirewall(ctx context.Context) *Evidence {
	type attempt struct {
		bin  string
		argv []string
	}
	attempts := []attempt{}
	if s.nftBin != "" {
		attempts = append(attempts, attempt{s.nftBin, []string{s.nftBin, "list", "ruleset"}})
	}
	if s.iptablesBin != "" {
		attempts = append(attempts, attempt{s.iptablesBin, []string{s.iptablesBin, "-S"}})
	}
	if len(attempts) == 0 || s.runner == nil {
		return &Evidence{
			Name: "firewall",
			Detail: i18n.T(ctx, "neither nft nor iptables is available here, so local firewall rules were "+
				"not inspected"),
		}
	}

	for _, a := range attempts {
		result, err := s.runner.Run(ctx, a.argv)
		if err != nil {
			continue
		}
		matches := greRules(result.Stdout)
		return &Evidence{
			Name: "firewall",
			Detail: i18n.T(ctx, "%s reported %d rule(s) mentioning protocol 47",
				a.bin, len(matches)),
			Data: map[string]any{
				"tool":       a.bin,
				"blocks_gre": blocksGre(matches),
				"rules":      matches,
			},
		}
	}
	return &Evidence{Name: "firewall", Detail: i18n.T(ctx, "the firewall rules could not be read")}
}

// greRules picks out the rules that mention protocol 47 by any of its names.
func greRules(ruleset string) []string {
	var out []string
	for _, line := range strings.Split(ruleset, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "gre") || strings.Contains(lower, "proto 47") ||
			strings.Contains(lower, "protocol 47") || strings.Contains(lower, "-p 47") ||
			strings.Contains(lower, "ip protocol 47") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

// blocksGre reports whether any matching rule drops or rejects.
func blocksGre(rules []string) bool {
	for _, rule := range rules {
		lower := strings.ToLower(rule)
		if strings.Contains(lower, "drop") || strings.Contains(lower, "reject") ||
			strings.Contains(lower, "deny") {
			return true
		}
	}
	return false
}

// capture takes a brief packet capture to prove whether GRE packets are
// actually leaving or arriving, which is strong evidence for the two
// traffic-shape verdicts (§13.4).
func (s *Service) capture(ctx context.Context, params AnalyzeParams, observed link.Link, rec tunnel.Record) *Evidence {
	allowed := s.settings == nil || s.settings.Bool("diagnostics.allow_tcpdump")
	if !allowed {
		return &Evidence{Name: "capture", Detail: i18n.T(ctx, "packet capture is switched off in the settings")}
	}
	if !params.Capture {
		return nil
	}
	if s.tcpdumpBin == "" || s.runner == nil {
		return &Evidence{Name: "capture",
			Detail: i18n.T(ctx, "tcpdump is not installed here, so nothing was captured")}
	}

	device := observed.Name
	if rec.BindDevice != nil && *rec.BindDevice != "" {
		device = *rec.BindDevice
	} else if underlay := s.underlayDevice(ctx, rec.LocalEndpoint); underlay != "" {
		device = underlay
	}

	captureCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	// A bounded capture: a handful of packets or a few seconds, whichever comes
	// first. It is evidence, not monitoring.
	result, err := s.runner.Run(captureCtx, []string{
		s.tcpdumpBin, "-ni", device, "-c", "5", "proto", "gre",
	})
	detail := i18n.T(ctx, "captured on %s", device)
	if err != nil {
		detail = i18n.T(ctx, "the capture on %s ended without seeing five GRE packets", device)
	}
	return &Evidence{
		Name:   "capture",
		Detail: detail,
		Data:   map[string]any{"device": device, "output": strings.TrimSpace(result.Stderr + "\n" + result.Stdout)},
	}
}

// underlayDevice finds the interface holding the local endpoint, which is where
// the encapsulated packets actually leave from.
func (s *Service) underlayDevice(ctx context.Context, localEndpoint string) string {
	if localEndpoint == "" {
		return ""
	}
	links, err := s.links.List(ctx)
	if err != nil {
		return ""
	}
	for _, l := range links {
		for _, addr := range l.Addresses {
			if addr.Address == localEndpoint {
				return l.Name
			}
		}
	}
	return ""
}

func saturating(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
