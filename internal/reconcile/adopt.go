package reconcile

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// AdoptRequest asks the panel to take over an interface that already exists.
type AdoptRequest struct {
	InterfaceName string `json:"interface_name"`
	// TunnelSideID overrides the slot. For a tunnel the old script created the
	// slot is inferred from the name and this is not needed.
	TunnelSideID *int64 `json:"tunnel_side_id,omitempty"`
	// PersistenceTypeID overrides how the adopted tunnel is persisted. By
	// default it keeps whatever it already has.
	PersistenceTypeID *int64 `json:"persistence_type_id,omitempty"`
	AddressPoolID     *int64 `json:"address_pool_id,omitempty"`
	Note              string `json:"note,omitempty"`
	// Takeover rewrites the unit file that currently owns this interface in the
	// panel's corrected format, after backing the original up (§12, §17.3).
	Takeover bool `json:"takeover,omitempty"`
}

// AdoptResult reports what was imported and what was touched.
type AdoptResult struct {
	Tunnel   tunnel.Record      `json:"tunnel"`
	Legacy   *LegacyInfo        `json:"legacy,omitempty"`
	Imported map[string]any     `json:"imported"`
	Warnings []validate.Warning `json:"warnings,omitempty"`
	// UnitsTakenOver and Backups record the files the panel now owns and where
	// the originals were saved.
	UnitsTakenOver []string `json:"units_taken_over,omitempty"`
	Backups        []string `json:"backups,omitempty"`
	// InterfaceBounced is always false and is reported so the answer to "did
	// adopting this interrupt my tunnel?" is explicit rather than implied.
	InterfaceBounced bool `json:"interface_bounced"`
}

// Warning codes specific to adoption.
const (
	WarnLegacyUnitNotOwned = "LEGACY_UNIT_NOT_OWNED"
	WarnNoPeerAddress      = "NO_PEER_ADDRESS"
	WarnPublicRangeAdopted = "PUBLIC_RANGE_ADOPTED"
	// WarnEspKeyRegenerated is raised when an ESP tunnel is adopted: the key
	// material is not readable from the kernel, so the panel generates a
	// fresh key and the far end must be given it before the tunnel carries
	// anything again.
	WarnEspKeyRegenerated = "ESP_KEY_REGENERATED"
	// WarnWssTokenRegenerated is raised when a GRE-over-WSS tunnel is
	// adopted: the token lives in the relay's memory, not in the kernel, so
	// the panel generates a fresh token and the far end must be given it
	// before the tunnel carries anything again.
	WarnWssTokenRegenerated = "WSS_TOKEN_REGENERATED"
	// WarnOmniKeyRegenerated is raised when an OmniTunnel tunnel is adopted:
	// the key lives in the binary's memory, not in the kernel, so the panel
	// generates a fresh key and the far end must be given it before the
	// tunnel carries anything again.
	WarnOmniKeyRegenerated = "OMNI_KEY_REGENERATED"
	WarnUnitNotActive      = "ADOPTED_UNIT_NOT_ACTIVE"
)

// Adopt imports an existing tunnel into the panel (§12).
//
// Adoption is strictly non-disruptive. Every parameter is read from the kernel,
// nothing is written to the interface, and the name is kept exactly as it is:
// renaming an interface tears the link down, which would defeat the entire
// purpose of adopting a working tunnel instead of rebuilding it.
func (s *Service) Adopt(ctx context.Context, req AdoptRequest) (AdoptResult, error) {
	name := strings.TrimSpace(req.InterfaceName)
	if err := validate.InterfaceName(name); err != nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName, validate.InterfaceNameMessage(ctx, name), nil)
		return AdoptResult{}, errs
	}

	observed, err := s.Links.Get(ctx, name)
	if err != nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName,
			i18n.T(ctx, "No interface called %q exists on this host.", name), nil)
		return AdoptResult{}, errs
	}
	if !observed.IsTunnel() {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName,
			i18n.T(ctx, "%q is a %s interface, not a tunnel. The panel manages tunnels only.",
				name, observed.Kind), nil)
		return AdoptResult{}, errs
	}
	if existing, err := s.Repo.ByInterfaceName(ctx, name); err == nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeNameConflict,
			i18n.T(ctx, "The panel already manages %q as tunnel %d.", name, existing.TunnelID), nil)
		return AdoptResult{}, errs
	}

	result := AdoptResult{Imported: map[string]any{}}
	legacy, isLegacy := ParseLegacyName(name)

	in, warnings, err := s.importFrom(ctx, observed, req, legacy, isLegacy)
	if err != nil {
		return AdoptResult{}, err
	}
	result.Warnings = warnings

	// The unit file decides how this tunnel is persisted, unless the request
	// says otherwise.
	unitPath := s.Store.UnitPath(name)
	unitExists := persist.Exists(unitPath)
	unitOwned := false
	if unitExists {
		unitOwned, _ = persist.IsPanelOwned(unitPath)
	}
	if req.PersistenceTypeID != nil {
		in.PersistenceTypeID = *req.PersistenceTypeID
	} else if unitExists {
		in.PersistenceTypeID = model.PersistenceTypeSystemd
	} else {
		in.PersistenceTypeID = model.PersistenceTypeRuntime
	}

	if isLegacy {
		legacy.UnitPath = ""
		if unitExists {
			legacy.UnitPath = unitPath
			legacy.IsPanelOwned = unitOwned
		}
		keepalivePath := filepath.Join(s.Store.SystemdDir, legacyKeepalivePrefix+name+persist.UnitSuffix)
		if persist.Exists(keepalivePath) {
			legacy.KeepalivePath = keepalivePath
		}
		result.Legacy = &legacy
	}

	// Only the syntactic rules apply here: the tunnel already exists, so the
	// conflict rules would object to the very interface being adopted.
	if errs := validate.ValidateStaticContext(ctx, in); !errs.Empty() {
		return AdoptResult{}, errs
	}

	// IsNameTemplated is deliberately false: this name came from somewhere else
	// and regenerating it from the template later would rename the interface
	// and tear the tunnel down (§12).
	id, err := s.Repo.Insert(ctx, in, true, false)
	if err != nil {
		return AdoptResult{}, err
	}
	// The tunnel is already running exactly as described, so it is Applied from
	// the moment it is adopted; nothing was changed to make that true.
	if err := s.Repo.SetApplyStatus(ctx, id, model.ApplyStatusApplied, nil); err != nil {
		return AdoptResult{}, err
	}

	if req.Takeover && unitExists && !unitOwned {
		taken, backups, err := s.takeOverUnits(ctx, name, id, isLegacy)
		if err != nil {
			return AdoptResult{}, err
		}
		result.UnitsTakenOver = taken
		result.Backups = backups

		// The interface is deliberately not bounced, so the rewritten unit has
		// not run. Saying so is the difference between this panel and the script
		// it replaces, which reported units it had never successfully started.
		if active, state, err := s.Store.IsActive(ctx, persist.UnitName(name)); err == nil && !active {
			result.Warnings = append(result.Warnings, validate.Warning{
				Code:  WarnUnitNotActive,
				Field: "takeover",
				Message: i18n.T(ctx, "The unit %s is %s: the interface was left running untouched, so the "+
					"rewritten unit has not been run and a reboot is the first time it would be. Reapply "+
					"this tunnel during a maintenance window to prove it works, which briefly interrupts it.",
					persist.UnitName(name), state),
				Details: map[string]any{"unit": persist.UnitName(name), "state": state},
			})
		}
	} else if unitExists && !unitOwned {
		result.Warnings = append(result.Warnings, validate.Warning{
			Code:  WarnLegacyUnitNotOwned,
			Field: "takeover",
			Message: i18n.T(ctx, "%s still owns this interface at boot and was not written by the panel. "+
				"Until you adopt with takeover, the panel will refuse to change or remove it, and a "+
				"reboot applies whatever that file says.", unitPath),
			Details: map[string]any{"unit_path": unitPath},
		})
	}

	stored, err := s.Repo.ByID(ctx, id)
	if err != nil {
		return AdoptResult{}, err
	}
	result.Tunnel = stored
	result.Imported = importedSummary(observed)
	result.InterfaceBounced = false
	return result, nil
}

// importFrom builds the tunnel description from what the kernel reports.
func (s *Service) importFrom(ctx context.Context, observed link.Link, req AdoptRequest,
	legacy LegacyInfo, isLegacy bool) (validate.TunnelInput, []validate.Warning, error) {

	// The kernel cannot tell one TUN-relay tunnel from another: `ip link`
	// reports every TUN interface as kind "tun", which the manager reads
	// as GRE-over-WSS. The panel-owned artifacts decide which relay owns
	// it: an EZTunnel JSON config in the panel's config directory means
	// EZTunnel, a unit whose command line runs omnitun means OmniTunnel,
	// and anything else stays GRE-over-WSS. Without this a real
	// EZTunnel or OmniTunnel interface would be adopted as GRE-over-WSS
	// and its settings would be unrecoverable.
	if observed.Kind == link.KindGREWSS {
		if s.Renderer != nil {
			if raw, err := os.ReadFile(s.Renderer.EzConfigPath(observed.Name)); err == nil {
				if _, err := link.ParseEzConfig(raw); err == nil {
					observed.Kind = link.KindEZTunnel
				}
			}
		}
		if observed.Kind == link.KindGREWSS {
			if _, _, _, _, _, ok := readOmniUnit(s.Store.UnitPath(observed.Name)); ok {
				observed.Kind = link.KindOmniTunnel
			}
		}
	}

	typeID, ok := model.TunnelTypeForKind(observed.Kind)
	if !ok {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidType,
			i18n.T(ctx, "%q is a %s interface, which this panel does not model.",
				observed.Name, observed.Kind), nil)
		return validate.TunnelInput{}, nil, errs
	}

	in := validate.TunnelInput{
		TunnelTypeID:  typeID,
		InterfaceName: observed.Name,
		Mtu:           int64(observed.MTU),
		Tos:           "inherit",
		AddressPoolID: req.AddressPoolID,
		IsEnabled:     observed.IsUp,
	}

	switch {
	case req.TunnelSideID != nil:
		in.TunnelSideID = *req.TunnelSideID
	case isLegacy:
		// The script gave its first side marker the .1 address and the second the
		// .2 address, which is exactly the panel's slot rule, so the mapping
		// carries over without guessing.
		in.TunnelSideID = legacy.TunnelSideID
	default:
		in.TunnelSideID = model.TunnelSideA
	}
	if isLegacy {
		number := legacy.TunnelNumber
		in.TunnelNumber = &number
	}

	if observed.Tunnel != nil {
		t := observed.Tunnel
		in.LocalEndpoint = t.Local
		in.RemoteEndpoint = t.Remote
		in.Ttl = int64(t.Ttl)
		in.BindDevice = t.BindDevice
		in.HasInputChecksum = t.HasInputChecksum
		in.HasOutputChecksum = t.HasOutputChecksum
		in.HasInputSequence = t.HasInputSequence
		in.HasOutputSequence = t.HasOutputSequence
		in.IsPathMtuDiscovery = t.IsPathMtuDiscovery
		in.IsIgnoreDf = t.IsIgnoreDf
		if t.Tos != "" {
			in.Tos = t.Tos
		}
		in.IKey = keyInt(t.IKey)
		in.OKey = keyInt(t.OKey)
		if t.FwMark != nil {
			mark := int64(*t.FwMark)
			in.FwMark = &mark
		}
		if t.HopLimit != nil {
			hop := int64(*t.HopLimit)
			in.HopLimit = &hop
		}
		if t.EncapLimit != nil {
			limit := int64(*t.EncapLimit)
			in.EncapLimit = &limit
		}
	}

	var warnings []validate.Warning
	// An ESP tunnel's key is not readable from the kernel — `ip xfrm state`
	// shows the algorithm and the SPI, never the key material — so the
	// adopted tunnel gets a fresh key here (adoption bypasses the service's
	// creation path, which is where a key is normally generated) and the far
	// end must be re-paired with it. Without the warning the tunnel would
	// come up looking healthy and carry nothing, which is exactly the silent
	// failure adoption is supposed to prevent.
	if observed.Kind == link.KindESP {
		warnings = append(warnings, validate.Warning{
			Code:  WarnEspKeyRegenerated,
			Field: "esp_key",
			Message: i18n.T(ctx, "The ESP key cannot be read from the kernel, so this tunnel gets a fresh "+
				"one. Give the far end the new key before it can carry traffic again."),
		})
		key, err := link.GenerateEspKey()
		if err != nil {
			return validate.TunnelInput{}, nil, err
		}
		in.EspKey = &key
	}
	// A GRE-over-WSS tunnel's token lives in the relay's memory, not in the
	// kernel, so the adopted tunnel gets a fresh token the same way, and
	// the far end must be re-paired with it.
	if observed.Kind == link.KindGREWSS {
		warnings = append(warnings, validate.Warning{
			Code:  WarnWssTokenRegenerated,
			Field: "wss_token",
			Message: i18n.T(ctx, "The WSS token cannot be read from the kernel, so this tunnel gets a fresh "+
				"one. Give the far end the new token before it can carry traffic again."),
		})
		token, err := link.GenerateWssToken()
		if err != nil {
			return validate.TunnelInput{}, nil, err
		}
		in.WssToken = &token
	}
	// An OmniTunnel tunnel's key lives in the binary's memory, not in the
	// kernel, so the adopted tunnel gets a fresh key the same way, and the
	// far end must be re-paired with it. The transport and the endpoints
	// are not readable from the kernel either — a TUN reports neither — so
	// they are recovered from the panel-owned unit file, which carries the
	// exact omnitun command line. Without a panel-owned unit they stay
	// empty and validation refuses the adoption honestly, rather than
	// adopting a tunnel with endpoints nobody knows.
	if observed.Kind == link.KindOmniTunnel {
		warnings = append(warnings, validate.Warning{
			Code:  WarnOmniKeyRegenerated,
			Field: "omni_key",
			Message: i18n.T(ctx, "The OmniTunnel key cannot be read from the kernel, so this tunnel gets a fresh "+
				"one. Give the far end the new key before it can carry traffic again."),
		})
		key, err := link.GenerateOmniKey()
		if err != nil {
			return validate.TunnelInput{}, nil, err
		}
		in.OmniKey = &key
		if transport, local, remote, port, conns, ok := readOmniUnit(s.Store.UnitPath(observed.Name)); ok {
			in.OmniTransport = &transport
			in.LocalEndpoint = local
			in.RemoteEndpoint = remote
			if port != 0 {
				p := int64(port)
				in.OmniPort = &p
			}
			if conns != 0 {
				c := int64(conns)
				in.OmniConns = &c
			}
		}
	}
	// An EZTunnel tunnel's settings are not readable from the kernel either
	// — a TUN reports neither transport nor port — so they are recovered
	// from the panel-owned JSON config, which carries the whole tunnel:
	// the mode, the transport, the port, the per-transport settings and,
	// for a raw carrier, both underlay endpoints. The key comes back with
	// them: the panel wrote this file itself (0600), so the adopted tunnel
	// keeps the key it already has and carries on working without
	// re-pairing. Without a panel-owned config they stay empty and
	// validation refuses the adoption honestly, rather than adopting a
	// tunnel with settings nobody knows.
	if observed.Kind == link.KindEZTunnel && s.Renderer != nil {
		if raw, err := os.ReadFile(s.Renderer.EzConfigPath(observed.Name)); err == nil {
			if cfg, err := link.ParseEzConfig(raw); err == nil {
				in.EzTransport = &cfg.Transport
				in.EzKey = &cfg.Key
				// The endpoints are whatever the config names: both for a
				// raw carrier, the peer only for a client, neither for a
				// server. What it does not name stays empty and validation
				// refuses the adoption honestly, rather than adopting a
				// tunnel with endpoints nobody knows.
				if cfg.LocalEndpoint != "" {
					in.LocalEndpoint = cfg.LocalEndpoint
				}
				if cfg.RemoteEndpoint != "" {
					in.RemoteEndpoint = cfg.RemoteEndpoint
				}
				if cfg.Port != 0 {
					p := int64(cfg.Port)
					in.EzPort = &p
				}
				if cfg.HttpPath != "" {
					in.EzHttpPath = &cfg.HttpPath
				}
				if cfg.XhttpMode != "" {
					in.EzXhttpMode = &cfg.XhttpMode
				}
				if cfg.XhttpHost != "" {
					in.EzXhttpHost = &cfg.XhttpHost
				}
				if cfg.RawProfile != "" {
					in.EzRawProfile = &cfg.RawProfile
				}
				if cfg.RawInterface != "" {
					in.EzRawInterface = &cfg.RawInterface
				}
				if cfg.MirageUplink != "" {
					in.EzMirageUplink = &cfg.MirageUplink
				}
				if cfg.MirageDownlink != "" {
					in.EzMirageDownlink = &cfg.MirageDownlink
				}
				if cfg.SpoofSources != nil {
					in.EzSpoofSources = &cfg.SpoofSources
				}
				if cfg.MirageExpected != nil {
					in.EzMirageExpected = &cfg.MirageExpected
				}
				// The mode is the side: a server listens, a client dials.
				// It overrides the default side, never an explicit
				// override the operator gave in the request.
				if req.TunnelSideID == nil {
					switch cfg.Mode {
					case link.EzModeServer:
						in.TunnelSideID = model.TunnelSideA
					case link.EzModeClient:
						in.TunnelSideID = model.TunnelSideB
					}
				}
			}
		}
	}
	for _, addr := range observed.Addresses {
		if addr.Scope == "link" {
			continue // the kernel's own link-local address, not configuration
		}
		imported := validate.AddressInput{
			Address:      addr.Address,
			PrefixLength: addr.PrefixLength,
			PeerAddress:  addr.Peer,
			IsPrimary:    len(in.Addresses) == 0,
		}
		if imported.PeerAddress == "" {
			if peer, ok := peerWithinSubnet(addr); ok {
				imported.PeerAddress = peer
			} else {
				warnings = append(warnings, validate.Warning{
					Code:  WarnNoPeerAddress,
					Field: "addresses",
					Message: i18n.T(ctx, "The peer address for %s could not be worked out from its subnet, "+
						"so monitoring has no target until you set one.", addr),
					Details: map[string]any{"address": addr.String()},
				})
			}
		}
		if parsed, err := netip.ParseAddr(addr.Address); err == nil && validate.IsPublicRange(parsed) {
			warnings = append(warnings, validate.Warning{
				Code:  WarnPublicRangeAdopted,
				Field: "addresses",
				Message: i18n.T(ctx, "This tunnel uses %s, which is globally routable. It is adopted as it "+
					"is, but it squats on address space belonging to someone else and blackholes those "+
					"destinations from this server.", addr),
				Details: map[string]any{"address": addr.String()},
			})
		}
		in.Addresses = append(in.Addresses, imported)
	}
	return in, warnings, nil
}

// peerWithinSubnet works out the other end's address from a point-to-point
// subnet: on a /30 or /31 there is exactly one other usable address.
func peerWithinSubnet(addr link.Address) (string, bool) {
	prefix, err := addr.Prefix()
	if err != nil {
		return "", false
	}
	self := prefix.Addr()
	network := prefix.Masked()

	// Only a two-address point-to-point subnet has an unambiguous answer. On
	// anything wider the peer could be any of several addresses, and guessing
	// would give monitoring a target that is not the other end of the tunnel.
	switch {
	case self.Is4() && (prefix.Bits() == 30 || prefix.Bits() == 31):
	case !self.Is4() && (prefix.Bits() == 126 || prefix.Bits() == 127):
	default:
		return "", false
	}

	first := network.Addr()
	if (self.Is4() && prefix.Bits() == 30) || (!self.Is4() && prefix.Bits() == 126) {
		first = first.Next() // skip the network address
	}
	second := first.Next()

	switch self {
	case first:
		return second.String(), true
	case second:
		return first.String(), true
	}
	return "", false
}

func importedSummary(observed link.Link) map[string]any {
	out := map[string]any{
		"interface_name": observed.Name,
		"kind":           observed.Kind,
		"mtu":            observed.MTU,
		"oper_state":     observed.OperState,
		"is_up":          observed.IsUp,
	}
	if observed.Tunnel != nil {
		out["local_endpoint"] = observed.Tunnel.Local
		out["remote_endpoint"] = observed.Tunnel.Remote
		out["ttl"] = observed.Tunnel.Ttl
		out["ikey"] = keyInt(observed.Tunnel.IKey)
		out["okey"] = keyInt(observed.Tunnel.OKey)
	}
	addresses := make([]string, 0, len(observed.Addresses))
	for _, a := range observed.Addresses {
		addresses = append(addresses, a.String())
	}
	out["addresses"] = addresses
	return out
}

// takeOverUnits rewrites the unit files that currently own an adopted interface
// in the panel's corrected format, backing each original up first (§12, §17.3).
//
// The interface itself is not touched. The unit is a oneshot that systemd
// already considers active, so rewriting the file and reloading does not stop
// or restart anything; a reboot is when the corrected version takes effect.
func (s *Service) takeOverUnits(ctx context.Context, name string, id int64, isLegacy bool) ([]string, []string, error) {
	rec, err := s.Repo.ByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	var taken, backups []string
	unitPath := s.Store.UnitPath(name)
	body := s.Renderer.Unit(tunnel.SpecOf(rec), tunnel.AddressesOf(rec))

	backup, err := s.Store.Write(ctx, unitPath, body, true)
	if err != nil {
		return nil, nil, i18n.Errorf(ctx, "taking over %s: %w", unitPath, err)
	}
	taken = append(taken, unitPath)
	if backup != "" {
		backups = append(backups, backup)
	}

	// The script's separate keepalive unit is superseded by the panel's own
	// prober, so it is backed up and removed rather than rewritten.
	if isLegacy {
		keepalivePath := filepath.Join(s.Store.SystemdDir, legacyKeepalivePrefix+name+persist.UnitSuffix)
		if persist.Exists(keepalivePath) {
			unit := legacyKeepalivePrefix + name + persist.UnitSuffix
			_ = s.Store.Stop(ctx, unit)
			_ = s.Store.Disable(ctx, unit)
			backup, err := s.Store.Remove(ctx, keepalivePath, true)
			if err != nil {
				return taken, backups, i18n.Errorf(ctx, "taking over %s: %w", keepalivePath, err)
			}
			taken = append(taken, keepalivePath)
			if backup != "" {
				backups = append(backups, backup)
			}
		}
	}

	if err := s.Store.DaemonReload(ctx); err != nil {
		return taken, backups, err
	}
	// Enabling is safe: it creates a symlink and does not start, stop or
	// otherwise disturb the running interface.
	if err := s.Store.Enable(ctx, persist.UnitName(name)); err != nil {
		return taken, backups, err
	}
	return taken, backups, nil
}

// readOmniUnit recovers an OmniTunnel tunnel's transport, endpoints, port and
// parallel-link count from a panel-owned unit file's ExecStart line. The
// kernel reports none of these for a TUN interface, but the unit carries the
// exact omnitun command line the panel wrote. Only the panel's own units are
// parsed: a hand-written unit's format is not the panel's to assume. The key
// is deliberately not read — adoption generates a fresh one, and the far end
// must be re-paired with it.
func readOmniUnit(path string) (transport, local, remote string, port, conns int, ok bool) {
	owned, err := persist.IsPanelOwned(path)
	if err != nil || !owned {
		return "", "", "", 0, 0, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", 0, 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		argv := splitUnitCommand(strings.TrimPrefix(line, "ExecStart="))
		if len(argv) < 2 || filepath.Base(argv[0]) != "omnitun" {
			return "", "", "", 0, 0, false
		}
		if !link.OmniTransportValid(argv[1]) {
			return "", "", "", 0, 0, false
		}
		transport = argv[1]
		for i := 2; i < len(argv); i++ {
			switch argv[i] {
			case "-L":
				if i+1 < len(argv) {
					local = argv[i+1]
					i++
				}
			case "-R":
				if i+1 < len(argv) {
					remote = argv[i+1]
					i++
				}
			case "-p":
				if i+1 < len(argv) {
					port, _ = strconv.Atoi(argv[i+1])
					i++
				}
			case "-N":
				if i+1 < len(argv) {
					conns, _ = strconv.Atoi(argv[i+1])
					i++
				}
			}
		}
		if local == "" || remote == "" {
			return "", "", "", 0, 0, false
		}
		return transport, local, remote, port, conns, true
	}
	return "", "", "", 0, 0, false
}

// splitUnitCommand splits a systemd ExecStart line into arguments, honouring
// the double quotes the panel's renderer writes around arguments that
// contain spaces. An omnitun command line has no such arguments, but the
// split is shared with any unit the panel writes.
func splitUnitCommand(s string) []string {
	var argv []string
	var cur strings.Builder
	var quoted bool
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' || r == '\t':
			if quoted {
				cur.WriteRune(r)
			} else if cur.Len() > 0 {
				argv = append(argv, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		argv = append(argv, cur.String())
	}
	return argv
}
