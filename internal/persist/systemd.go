// Package persist renders the files that make a tunnel survive a reboot: a
// systemd unit, a pair of systemd-networkd files, or nothing at all for a
// runtime-only tunnel (§9.4).
//
// The unit deliberately corrects every defect of the one the legacy script
// wrote. It orders after network-online.target rather than network.target,
// carries no Restart= on a oneshot unit where the directive is inert, cleans up
// any leftover device before creating one so a restart cannot fail on it,
// tolerates its stop steps so stopping an already-stopped tunnel succeeds, and
// identifies itself as panel-owned so the panel never deletes a file it did not
// write.
//
// Note the asymmetry with the rest of the panel: the running kernel is
// configured through netlink, while the unit file uses `ip`, so it stays
// readable, auditable and functional with the panel uninstalled. Both paths are
// built from the same argv builder in internal/link, so they cannot diverge.
package persist

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/link"
)

// OwnershipMarker identifies a file this panel wrote. Its presence is what
// makes it safe to overwrite or delete a unit; its absence is what makes it
// forbidden without an explicit takeover (§17.3).
const OwnershipMarker = "# gre-panel:managed=1"

// UnitSuffix is the systemd unit file extension.
const UnitSuffix = ".service"

// KeepalivePrefix is the unit name prefix of the optional keepalive unit (§9.5).
const KeepalivePrefix = "gre-panel-keepalive-"

// Default binary paths, used only when nothing better was resolved at startup.
// They are fields rather than constants everywhere else precisely because the
// legacy script hardcoding /sbin/ip is one of the defects being corrected.
const (
	DefaultIPBin       = "/sbin/ip"
	DefaultModprobeBin = "/sbin/modprobe"
	DefaultPingBin     = "/bin/ping"
	DefaultPanelBin    = "/usr/local/bin/gre-panel"
	DefaultOmniBin     = "/var/lib/gre-panel/bin/omnitun"
)

// Renderer turns a tunnel into the files that persist it.
type Renderer struct {
	IPBin       string
	ModprobeBin string
	PingBin     string
	// PanelBin is the path to the gre-panel binary itself, which a
	// GRE-over-WSS unit runs as its relay.
	PanelBin string
	// OmniBin is the path to the omnitun binary, which an OmniTunnel unit
	// runs. It is installed by the panel itself and verified against a
	// pinned checksum before it is used.
	OmniBin string
}

// NewRenderer returns a renderer using the given binaries, falling back to the
// conventional locations for any that were not resolved.
func NewRenderer(ipBin, modprobeBin, pingBin string) *Renderer {
	return &Renderer{
		IPBin:       orDefault(ipBin, DefaultIPBin),
		ModprobeBin: orDefault(modprobeBin, DefaultModprobeBin),
		PingBin:     orDefault(pingBin, DefaultPingBin),
		PanelBin:    DefaultPanelBin,
		OmniBin:     DefaultOmniBin,
	}
}

// WithPanelBin sets the path to the gre-panel binary, which a GRE-over-WSS
// unit runs as its relay. It returns the renderer for chaining.
func (r *Renderer) WithPanelBin(bin string) *Renderer {
	r.PanelBin = orDefault(bin, DefaultPanelBin)
	return r
}

// WithOmniBin sets the path to the omnitun binary, which an OmniTunnel unit
// runs. It returns the renderer for chaining.
func (r *Renderer) WithOmniBin(bin string) *Renderer {
	r.OmniBin = orDefault(bin, DefaultOmniBin)
	return r
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// UnitName is the systemd unit file name for a tunnel. It is the interface
// name, which is what the legacy script used too, so a tunnel it created is
// taken over by rewriting the same path rather than by leaving two units
// fighting over one interface (§12).
func UnitName(interfaceName string) string { return interfaceName + UnitSuffix }

// KeepaliveUnitName is the unit file name of the optional keepalive unit.
func KeepaliveUnitName(interfaceName string) string {
	return KeepalivePrefix + interfaceName + UnitSuffix
}

// ModuleFor returns the kernel module a tunnel kind needs. It autoloads on
// first use, so the modprobe step is a tolerated hint rather than a
// requirement.
func ModuleFor(kind string) string {
	switch {
	case kind == link.KindESP:
		return "xfrm_interface"
	case kind == link.KindGREWSS:
		// The relay creates a TUN interface, which needs the tun module.
		return "tun"
	case kind == link.KindOmniTunnel:
		// The omnitun binary creates a TUN interface, which needs the tun
		// module.
		return "tun"
	case link.IsIPv6Kind(kind):
		return "ip6_gre"
	default:
		return "ip_gre"
	}
}

// Unit renders the systemd unit for a tunnel (§9.4).
func (r *Renderer) Unit(spec link.TunnelSpec, addresses []link.Address) string {
	// A GRE-over-WSS tunnel is carried by a long-running relay, not by a
	// kernel interface the unit creates once. Its unit is Type=simple and
	// restarts the relay when it exits, so the tunnel comes back on its own
	// after a crash and after a reboot.
	if spec.Kind == link.KindGREWSS {
		return r.relayUnit(spec, addresses)
	}
	if spec.Kind == link.KindOmniTunnel {
		return r.omnitunnelUnit(spec, addresses)
	}

	name := spec.Name
	var b strings.Builder

	b.WriteString(OwnershipMarker + " interface=" + name + "\n")
	b.WriteString("# This file is generated by gre-panel. Edit the tunnel in the panel; changes made\n")
	b.WriteString("# here are overwritten the next time it is applied.\n")
	b.WriteString("\n[Unit]\n")
	label := "GRE"
	if spec.Kind == link.KindESP {
		label = "ESP"
	}
	fmt.Fprintf(&b, "Description=%s Tunnel %s (managed by gre-panel)\n", label, name)
	// network-online.target, not network.target: the local endpoint address has
	// to exist before `ip link add local <A>` can succeed.
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=oneshot\n")
	b.WriteString("RemainAfterExit=yes\n")
	// Both pre-steps are tolerated with a leading dash: the module normally
	// autoloads, and deleting a device that is not there is the desired state
	// already. Without the delete, a restart after an unclean stop would fail on
	// the leftover interface, which is exactly the failure mode the legacy unit
	// had no answer for.
	fmt.Fprintf(&b, "ExecStartPre=-%s %s\n", r.ModprobeBin, ModuleFor(spec.Kind))
	fmt.Fprintf(&b, "ExecStartPre=-%s\n", join(link.DeleteArgs(r.IPBin, name)))
	// An ESP tunnel's associations outlive their interface, so a restart
	// would fail adding them a second time unless the leftovers are cleared
	// first. These deletes are tolerated: on a clean start there is nothing
	// to remove.
	if spec.Kind == link.KindESP {
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStartPre=-%s\n", join(link.XfrmStateDelArgs(r.IPBin, spec, outbound)))
		}
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStartPre=-%s\n", join(link.XfrmPolicyDelArgs(r.IPBin, spec, outbound)))
		}
	}

	fmt.Fprintf(&b, "ExecStart=%s\n", join(link.CreateArgs(r.IPBin, spec)))
	if spec.Kind == link.KindESP {
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStart=%s\n", join(link.XfrmStateAddArgs(r.IPBin, spec, outbound)))
		}
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStart=%s\n", join(link.XfrmPolicyAddArgs(r.IPBin, spec, outbound)))
		}
	}
	for _, addr := range addresses {
		fmt.Fprintf(&b, "ExecStart=%s\n", join(link.AddAddressArgs(r.IPBin, name, addr)))
	}
	if spec.Mtu > 0 {
		fmt.Fprintf(&b, "ExecStart=%s\n", join(link.SetMTUArgs(r.IPBin, name, spec.Mtu)))
	}
	if spec.TxQueueLength != nil {
		fmt.Fprintf(&b, "ExecStart=%s\n", join(link.SetTxQueueLenArgs(r.IPBin, name, *spec.TxQueueLength)))
	}
	fmt.Fprintf(&b, "ExecStart=%s\n", join(link.SetUpArgs(r.IPBin, name)))

	// Stop steps are tolerated too, so stopping a tunnel that is already gone
	// succeeds instead of leaving the unit in a failed state.
	fmt.Fprintf(&b, "ExecStop=-%s\n", join(link.SetDownArgs(r.IPBin, name)))
	if spec.Kind == link.KindESP {
		// The associations outlive the interface, so stopping the tunnel
		// removes them too; otherwise they would linger and block a later
		// tunnel with the same identity.
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStop=-%s\n", join(link.XfrmStateDelArgs(r.IPBin, spec, outbound)))
		}
		for _, outbound := range []bool{true, false} {
			fmt.Fprintf(&b, "ExecStop=-%s\n", join(link.XfrmPolicyDelArgs(r.IPBin, spec, outbound)))
		}
	}
	fmt.Fprintf(&b, "ExecStop=-%s\n", join(link.DeleteArgs(r.IPBin, name)))
	// Deliberately no Restart=: this is a Type=oneshot unit, where the directive
	// does nothing. The legacy unit carried Restart=on-failure and RestartSec=3,
	// which read as resilience and provided none.

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// KeepaliveOptions are the parameters of the optional keepalive unit (§9.5).
type KeepaliveOptions struct {
	// Source is the tunnel's own address, which the probe is sent from so it
	// egresses through the tunnel.
	Source string
	// Target is the peer's tunnel address.
	Target string
	// IntervalSeconds is the gap between packets.
	IntervalSeconds float64
	// PacketSize is the ICMP payload size in bytes.
	PacketSize int
}

// KeepaliveUnit renders the standalone keepalive unit (§9.5).
//
// This is offered only for operators who want keepalive to survive the panel
// being stopped. The default is monitor_only, because the panel's own prober
// already sends continuous ICMP from the tunnel source address and therefore is
// a keepalive, without one process per tunnel.
func (r *Renderer) KeepaliveUnit(interfaceName, kind string, opts KeepaliveOptions) string {
	var b strings.Builder

	b.WriteString(OwnershipMarker + " interface=" + interfaceName + " role=keepalive\n")
	b.WriteString("# This file is generated by gre-panel. Edit the tunnel in the panel; changes made\n")
	b.WriteString("# here are overwritten the next time it is applied.\n")
	b.WriteString("\n[Unit]\n")
	label := "GRE"
	if kind == link.KindESP {
		label = "ESP"
	}
	fmt.Fprintf(&b, "Description=%s Tunnel keepalive for %s (managed by gre-panel)\n", label, interfaceName)
	fmt.Fprintf(&b, "After=%s\n", UnitName(interfaceName))
	fmt.Fprintf(&b, "BindsTo=%s\n", UnitName(interfaceName))

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", join(KeepaliveArgs(r.PingBin, opts)))
	// Restart= belongs here and nowhere else in this package: this is a
	// long-running process, so restarting it is meaningful.
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// KeepaliveArgs builds the keepalive command. -O reports outstanding packets so
// the journal records loss rather than going silent, and -n skips reverse DNS,
// which a tunnel address will not answer anyway.
func KeepaliveArgs(pingBin string, opts KeepaliveOptions) []string {
	interval := opts.IntervalSeconds
	if interval <= 0 {
		interval = 1
	}
	size := opts.PacketSize
	if size <= 0 {
		size = 56
	}
	return []string{
		pingBin,
		"-I", opts.Source,
		"-O",
		"-i", trimFloat(interval),
		"-s", fmt.Sprintf("%d", size),
		"-n",
		opts.Target,
	}
}

// trimFloat renders an interval without trailing zeros, so 1.0 is "1".
func trimFloat(v float64) string {
	s := fmt.Sprintf("%.3f", v)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// join renders an argv slice for a unit file line. It is display formatting for
// a file systemd itself will split; nothing in this package ever hands a joined
// string to a shell (§17.6).
// join renders a command line for a unit file. An argument that contains a
// space is double-quoted, because systemd splits an ExecStart line on
// whitespace: without the quotes a value like "10.10.1.1 peer 10.10.1.2/30"
// would arrive as three arguments. Arguments without a space are left
// bare, so the ip commands the units have always rendered stay byte-identical.
func join(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		if strings.ContainsAny(arg, " \t\"") {
			parts = append(parts, strconv.Quote(arg))
		} else {
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " ")
}

// relayUnit renders the systemd unit for a GRE-over-WSS tunnel. The relay is
// a long-running process that owns the TUN interface, so the unit is
// Type=simple and restarts it when it exits; the relay configures the TUN
// (MTU, addresses, up) itself when it starts. Stopping the unit kills the
// relay, which closes the TUN and takes the interface with it.
func (r *Renderer) relayUnit(spec link.TunnelSpec, addresses []link.Address) string {
	name := spec.Name
	var b strings.Builder

	b.WriteString(OwnershipMarker + " interface=" + name + "\n")
	b.WriteString("# This file is generated by gre-panel. Edit the tunnel in the panel; changes made\n")
	b.WriteString("# here are overwritten the next time it is applied.\n")
	b.WriteString("\n[Unit]\n")
	fmt.Fprintf(&b, "Description=GRE over WSS Tunnel %s (managed by gre-panel)\n", name)
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	// The tun module normally autoloads; the pre-step is tolerated so a
	// start succeeds whether it was already loaded or not.
	fmt.Fprintf(&b, "ExecStartPre=-%s %s\n", r.ModprobeBin, ModuleFor(spec.Kind))
	// The relay runs until it is stopped. Restart= belongs here and nowhere
	// else in the tunnel units: this is a long-running process, so restarting
	// it is meaningful, and it is what brings the tunnel back after a crash
	// without the panel having to notice.
	fmt.Fprintf(&b, "ExecStart=%s\n", join(link.RelayArgs(r.PanelBin, spec, addresses)))
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	// The relay must not be killed mid-write: a clean SIGTERM lets it close
	// the WebSocket and the TUN in order.
	b.WriteString("KillMode=mixed\n")

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// omnitunnelUnit renders the systemd unit for an OmniTunnel tunnel. The
// omnitun binary is a long-running process that owns the TUN interface, so
// the unit is Type=simple and restarts it when it exits; the binary
// configures the TUN (MTU, addresses, up) itself when it starts. Stopping
// the unit kills the binary, which closes the TUN and takes the interface
// with it.
func (r *Renderer) omnitunnelUnit(spec link.TunnelSpec, addresses []link.Address) string {
	name := spec.Name
	var b strings.Builder

	b.WriteString(OwnershipMarker + " interface=" + name + "\n")
	b.WriteString("# This file is generated by gre-panel. Edit the tunnel in the panel; changes made\n")
	b.WriteString("# here are overwritten the next time it is applied.\n")
	b.WriteString("\n[Unit]\n")
	fmt.Fprintf(&b, "Description=OmniTunnel %s Tunnel %s (managed by gre-panel)\n", spec.OmniTransport, name)
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	// The tun module normally autoloads; the pre-step is tolerated so a
	// start succeeds whether it was already loaded or not.
	fmt.Fprintf(&b, "ExecStartPre=-%s %s\n", r.ModprobeBin, ModuleFor(spec.Kind))
	// The binary runs until it is stopped. Restart= belongs here and nowhere
	// else in the tunnel units: this is a long-running process, so restarting
	// it is meaningful, and it is what brings the tunnel back after a crash
	// without the panel having to notice.
	fmt.Fprintf(&b, "ExecStart=%s\n", join(link.OmniArgs(r.OmniBin, spec, addresses)))
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	// The binary must not be killed mid-write: a clean SIGTERM lets it close
	// the tunnel and the TUN in order.
	b.WriteString("KillMode=mixed\n")

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}
