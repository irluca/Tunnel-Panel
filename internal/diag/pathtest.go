package diag

import (
	"context"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
)

// PathTestParams tunes the path test.
type PathTestParams struct {
	// Count is how many probes the latency measurement sends. Ten is enough
	// to see loss and jitter without the test taking a minute.
	Count int `json:"count,omitempty"`
	// TimeoutSecs bounds each probe.
	TimeoutSecs float64 `json:"timeout_seconds,omitempty"`
}

// PathTestResult is one combined measurement of the path a tunnel runs on:
// how fast and how lossy it is, how large a packet fits, and how many hops
// it takes. It is the benchmark the path-test tab shows, and the comparison
// a carrier switch is judged against.
type PathTestResult struct {
	// Ping is the latency measurement through the tunnel.
	Ping *monitor.PingResult `json:"ping,omitempty"`
	// Mtu is the path MTU measurement and the tunnel MTU it recommends.
	Mtu *MtuResult `json:"mtu,omitempty"`
	// Traceroute is the hop walk to the remote endpoint.
	Traceroute *TracerouteResult `json:"traceroute,omitempty"`
	Summary    string            `json:"summary"`
	CheckedAt  string            `json:"checked_at"`
}

// PathTest measures the path in one go: latency and loss through the tunnel,
// the largest packet that fits, and the hops to the far end. Each part is
// optional in the sense that a part that cannot run is reported as such
// rather than failing the whole test: a path that answers pings but refuses
// traceroute is still a measurement worth having.
func (s *Service) PathTest(ctx context.Context, tunnelID int64, params PathTestParams) (Run, PathTestResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, PathTestResult{}, err
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypePathTest, params)
	if err != nil {
		return Run{}, PathTestResult{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	result := PathTestResult{}
	source, target := probeEndpoints(rec)
	count := params.Count
	if count <= 0 {
		count = 10
	}
	timeout := time.Second
	if params.TimeoutSecs > 0 {
		timeout = seconds(params.TimeoutSecs)
	}

	// 1. Latency and loss through the tunnel.
	if source != "" && target != "" {
		summary, err := monitor.Ping(runCtx, s.dialer, monitor.PingRequest{
			TunnelID: rec.TunnelID, Source: source, Target: target,
			Count: count, Interval: 200 * time.Millisecond, Timeout: timeout,
		}, nil)
		if err == nil {
			result.Ping = &summary
		}
	}

	// 2. The largest packet that fits, and the tunnel MTU it recommends.
	_, mtu, err := s.MtuProbe(runCtx, tunnelID, MtuParams{ProbeTunnel: true, TimeoutSecs: params.TimeoutSecs})
	if err == nil {
		result.Mtu = &mtu
	}

	// 3. The hops to the far end, over the underlay.
	_, trace, err := s.Traceroute(runCtx, tunnelID, TracerouteParams{MaxHops: 20, Probes: 1, TimeoutSecs: params.TimeoutSecs})
	if err == nil {
		result.Traceroute = &trace
	}

	result.Summary = pathTestSummary(ctx, result)
	result.CheckedAt = model.NowUTC()

	if err := s.finish(ctx, runID, result, true); err != nil {
		s.log.Error("recording a path test result failed", "run_id", runID, "error", err)
	}
	release()
	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypePathTest,
		Type: TypeName(model.DiagnosticTypePathTest), Params: params, Result: result, IsSuccess: true,
	})
	return run, result, nil
}

// pathTestSummary renders the one-line verdict of a path test: how fast, how
// lossy, and how large a packet fits.
func pathTestSummary(ctx context.Context, r PathTestResult) string {
	if r.Ping == nil {
		return i18n.T(ctx, "The path could not be measured: no probe through the tunnel was answered.")
	}
	average := "—"
	if r.Ping.RttAvgMs != nil {
		average = fmt.Sprintf("%.1f ms", *r.Ping.RttAvgMs)
	}
	summary := i18n.T(ctx, "%d of %d probes through the tunnel were answered, with an average round trip of %s and %.0f%% loss.",
		r.Ping.Received, r.Ping.Sent, average, r.Ping.LossPercent)
	if r.Mtu != nil && r.Mtu.DiscoveredPathMtu > 0 {
		summary += " " + i18n.T(ctx, "The largest packet that fits is %d bytes; the recommended tunnel MTU is %d.",
			r.Mtu.DiscoveredPathMtu, r.Mtu.RecommendedTunnelMtu)
	}
	if r.Traceroute != nil {
		summary += " " + i18n.T(ctx, "The path to the far end takes %d hops.", len(r.Traceroute.Hops))
	}
	return summary
}
