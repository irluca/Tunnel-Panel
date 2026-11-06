package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/validate"
)

// The binaries the tests pretend to have. Nothing is ever executed: the fake
// runner records the argv and the simulator below interprets it.
const (
	testIPBin        = "/sbin/ip"
	testSystemctlBin = "/bin/systemctl"
	testModprobeBin  = "/sbin/modprobe"
	testPingBin      = "/bin/ping"
)

// systemdSimulator answers systemctl calls by interpreting the unit files the
// panel actually wrote and applying their `ip` commands to the fake link
// manager.
//
// It is deliberately more work than stubbing "systemctl start" to success: it
// means a test of the apply pipeline also proves the rendered unit file
// produces the right kernel state, which is the equivalence the specification
// asks for and the thing the legacy script never checked.
type systemdSimulator struct {
	mu         sync.Mutex
	links      *link.Fake
	systemdDir string
	units      map[string]*unitState
	// FailUnitStart names a unit whose start fails, which is how a test forces an
	// apply failure and asserts the rollback.
	FailUnitStart string
	// FailIPCommand names a fragment of a command inside a unit that fails.
	FailIPCommand string
	// SkipCommands lists command fragments the simulated systemd silently does
	// not run, which is how a test produces a unit that starts successfully and
	// still leaves the kernel in the wrong state.
	SkipCommands []string
}

type unitState struct {
	enabled bool
	active  bool
}

func newSystemdSimulator(links *link.Fake, systemdDir string) *systemdSimulator {
	return &systemdSimulator{links: links, systemdDir: systemdDir, units: map[string]*unitState{}}
}

func (s *systemdSimulator) state(unit string) *unitState {
	if s.units[unit] == nil {
		s.units[unit] = &unitState{}
	}
	return s.units[unit]
}

// IsEnabled and IsActive expose the simulated state to assertions.
func (s *systemdSimulator) IsEnabled(unit string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state(unit).enabled
}

func (s *systemdSimulator) IsActive(unit string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state(unit).active
}

func (s *systemdSimulator) handle(argv []string) (exec.Result, error) {
	if len(argv) < 2 {
		return exec.Result{}, fmt.Errorf("unexpected command %v", argv)
	}
	switch filepath.Base(argv[0]) {
	case "systemctl":
		return s.systemctl(argv)
	case "journalctl":
		return exec.Result{Stdout: "-- no entries --"}, nil
	case "networkctl":
		return exec.Result{}, nil
	}
	return exec.Result{}, fmt.Errorf("the tests do not run %q", argv[0])
}

func (s *systemdSimulator) systemctl(argv []string) (exec.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	verb := argv[1]
	unit := ""
	if len(argv) > 2 {
		unit = argv[2]
	}

	switch verb {
	case "daemon-reload", "reset-failed", "reload-or-restart":
		return exec.Result{}, nil
	case "enable":
		s.state(unit).enabled = true
		return exec.Result{}, nil
	case "disable":
		s.state(unit).enabled = false
		return exec.Result{}, nil
	case "is-enabled":
		if s.state(unit).enabled {
			return exec.Result{Stdout: "enabled\n"}, nil
		}
		return exec.Result{ExitCode: 1, Stdout: "disabled\n"}, nil
	case "is-active":
		if s.state(unit).active {
			return exec.Result{Stdout: "active\n"}, nil
		}
		return exec.Result{ExitCode: 3, Stdout: "inactive\n"}, nil
	case "stop":
		s.state(unit).active = false
		if err := s.runUnit(unit, "ExecStop="); err != nil {
			return exec.Result{ExitCode: 1, Stderr: err.Error()}, err
		}
		return exec.Result{}, nil
	case "start", "restart":
		if unit == s.FailUnitStart {
			return exec.Result{ExitCode: 1, Stderr: "Job for " + unit + " failed"},
				fmt.Errorf("systemctl %s %s failed", verb, unit)
		}
		if err := s.runUnit(unit, "ExecStartPre=", "ExecStart="); err != nil {
			s.state(unit).active = false
			return exec.Result{ExitCode: 1, Stderr: err.Error()}, err
		}
		s.state(unit).active = true
		return exec.Result{}, nil
	}
	return exec.Result{}, fmt.Errorf("the simulator does not implement systemctl %s", verb)
}

// runUnit reads the unit file the panel wrote and carries out the lines with
// the given prefixes, in order.
func (s *systemdSimulator) runUnit(unit string, prefixes ...string) error {
	raw, err := os.ReadFile(filepath.Join(s.systemdDir, unit))
	if err != nil {
		return fmt.Errorf("unit %s does not exist", unit)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		for _, prefix := range prefixes {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			command := strings.TrimPrefix(line, prefix)
			tolerant := strings.HasPrefix(command, "-")
			command = strings.TrimPrefix(command, "-")
			if s.skipped(command) {
				continue
			}
			if s.FailIPCommand != "" && strings.Contains(command, s.FailIPCommand) && !tolerant {
				return fmt.Errorf("%s failed", command)
			}
			argv, err := splitCommand(command)
			if err != nil {
				return fmt.Errorf("%s failed: %w", command, err)
			}
			if err := s.interpret(argv); err != nil && !tolerant {
				return fmt.Errorf("%s failed: %w", command, err)
			}
		}
	}
	return nil
}

// skipped reports whether the simulated systemd quietly declines to run a
// command.
func (s *systemdSimulator) skipped(command string) bool {
	for _, fragment := range s.SkipCommands {
		if fragment != "" && strings.Contains(command, fragment) {
			return true
		}
	}
	return false
}

// interpret applies one command from a unit file to the fake link manager.
func (s *systemdSimulator) interpret(argv []string) error {
	ctx := context.Background()
	if len(argv) == 0 {
		return nil
	}
	switch filepath.Base(argv[0]) {
	case "modprobe", "ping":
		return nil
	case "gre-panel":
		// The relay unit runs the panel binary itself. The simulator models
		// the relay by creating the TUN it owns, with the MTU and addresses
		// the relay configures, and bringing it up — which is exactly what
		// the relay does when it starts.
		return s.interpretRelay(ctx, argv)
	case "omnitun":
		// The OmniTunnel unit runs the omnitun binary. The simulator models
		// it the same way: by creating the TUN it owns, with the MTU and
		// addresses it configures, and bringing it up.
		return s.interpretOmni(ctx, argv)
	case "ip":
	default:
		return fmt.Errorf("the simulator does not run %q", argv[0])
	}
	if len(argv) < 3 {
		return fmt.Errorf("incomplete ip command %v", argv)
	}

	switch {
	case argv[1] == "link" && argv[2] == "add":
		spec, err := parseCreate(argv)
		if err != nil {
			return err
		}
		return s.links.Create(ctx, spec)
	case argv[1] == "link" && argv[2] == "del":
		return s.links.Delete(ctx, argv[3])
	case argv[1] == "link" && argv[2] == "set":
		return s.interpretLinkSet(ctx, argv)
	case argv[1] == "addr" && argv[2] == "add":
		name, addr, err := parseAddress(argv)
		if err != nil {
			return err
		}
		return s.links.AddAddress(ctx, name, addr)
	case argv[1] == "addr" && argv[2] == "del":
		name, addr, err := parseAddress(argv)
		if err != nil {
			return err
		}
		return s.links.RemoveAddress(ctx, name, addr)
	case argv[1] == "xfrm" && argv[2] == "state":
		return s.interpretXfrmState(argv)
	case argv[1] == "xfrm" && argv[2] == "policy":
		return s.interpretXfrmPolicy(argv)
	}
	return fmt.Errorf("the simulator does not run %v", argv)
}

// parseXfrm extracts the SPI, interface identifier and direction from an
// `ip xfrm` command by scanning for their keywords, so the exact argument
// order the builders produce does not matter.
func parseXfrm(argv []string) (spi, ifid uint32, dir string, err error) {
	for i := 1; i < len(argv)-1; i++ {
		switch argv[i] {
		case "spi":
			n, perr := strconv.ParseUint(strings.TrimPrefix(argv[i+1], "0x"), 16, 32)
			if perr != nil {
				return 0, 0, "", perr
			}
			spi = uint32(n)
		case "if_id":
			n, perr := strconv.ParseUint(argv[i+1], 10, 32)
			if perr != nil {
				return 0, 0, "", perr
			}
			ifid = uint32(n)
		case "dir":
			dir = argv[i+1]
		}
	}
	return spi, ifid, dir, nil
}

func (s *systemdSimulator) interpretXfrmState(argv []string) error {
	if len(argv) < 4 {
		return fmt.Errorf("incomplete ip xfrm state command %v", argv)
	}
	spi, ifid, _, err := parseXfrm(argv)
	if err != nil {
		return err
	}
	switch argv[3] {
	case "add":
		s.links.RecordXfrmState(ifid, spi)
		return nil
	case "del":
		s.links.RemoveXfrmState(ifid, spi)
		return nil
	}
	return fmt.Errorf("the simulator does not run %v", argv)
}

func (s *systemdSimulator) interpretXfrmPolicy(argv []string) error {
	if len(argv) < 4 {
		return fmt.Errorf("incomplete ip xfrm policy command %v", argv)
	}
	_, ifid, dir, err := parseXfrm(argv)
	if err != nil {
		return err
	}
	switch argv[3] {
	case "add":
		s.links.RecordXfrmPolicy(ifid, dir)
		return nil
	case "del":
		s.links.RemoveXfrmPolicy(ifid, dir)
		return nil
	}
	return fmt.Errorf("the simulator does not run %v", argv)
}

func (s *systemdSimulator) interpretLinkSet(ctx context.Context, argv []string) error {
	// ip link set dev <name> <verb> [value]
	if len(argv) < 6 || argv[3] != "dev" {
		return fmt.Errorf("unexpected link set command %v", argv)
	}
	name := argv[4]
	switch argv[5] {
	case "up":
		return s.links.SetUp(ctx, name)
	case "down":
		return s.links.SetDown(ctx, name)
	case "mtu":
		mtu, err := strconv.Atoi(argv[6])
		if err != nil {
			return err
		}
		return s.links.SetMTU(ctx, name, mtu)
	case "txqueuelen":
		length, err := strconv.Atoi(argv[6])
		if err != nil {
			return err
		}
		return s.links.SetTxQueueLength(ctx, name, length)
	}
	return fmt.Errorf("unexpected link set verb %q", argv[5])
}

// parseCreate turns an `ip link add` command back into a specification, which
// is what makes the round trip through the unit file meaningful.
func parseCreate(argv []string) (link.TunnelSpec, error) {
	var spec link.TunnelSpec
	for i := 3; i < len(argv); i++ {
		switch argv[i] {
		case "name":
			i++
			spec.Name = argv[i]
		case "type":
			i++
			spec.Kind = argv[i]
			if spec.Kind == "xfrm" {
				// The kernel calls the interface type xfrm; the panel
				// calls the tunnel ESP. The real readback translates it
				// the same way (see normaliseKind in ipcmd.go).
				spec.Kind = link.KindESP
			}
		case "local":
			i++
			spec.Local = argv[i]
		case "remote":
			i++
			spec.Remote = argv[i]
		case "ttl", "hoplimit":
			i++
			if argv[i] != "inherit" {
				n, err := strconv.Atoi(argv[i])
				if err != nil {
					return spec, err
				}
				spec.Ttl = n
			}
		case "tos":
			i++
			spec.Tos = argv[i]
		case "ikey", "okey":
			key := argv[i]
			i++
			n, err := strconv.ParseUint(argv[i], 10, 32)
			if err != nil {
				return spec, err
			}
			value := uint32(n)
			if key == "ikey" {
				spec.IKey = &value
			} else {
				spec.OKey = &value
			}
		case "icsum":
			spec.HasInputChecksum = true
		case "ocsum":
			spec.HasOutputChecksum = true
		case "iseq":
			spec.HasInputSequence = true
		case "oseq":
			spec.HasOutputSequence = true
		case "pmtudisc":
			spec.IsPathMtuDiscovery = true
		case "nopmtudisc":
			spec.IsPathMtuDiscovery = false
		case "ignore-df":
			spec.IsIgnoreDf = true
		case "dev":
			i++
			spec.BindDevice = argv[i]
		case "fwmark":
			i++
			n, err := strconv.ParseUint(argv[i], 10, 32)
			if err != nil {
				return spec, err
			}
			mark := uint32(n)
			spec.FwMark = &mark
		case "encaplimit":
			i++
			n, _ := strconv.Atoi(argv[i])
			spec.EncapLimit = &n
		case "flowlabel":
			i++
			spec.FlowLabel = argv[i]
		case "if_id":
			i++
			n, err := strconv.ParseUint(argv[i], 10, 32)
			if err != nil {
				return spec, err
			}
			spec.EspIfID = uint32(n)
		}
	}
	if spec.Name == "" || spec.Kind == "" {
		return spec, fmt.Errorf("the create command names no interface or type: %v", argv)
	}
	return spec, nil
}

func parseAddress(argv []string) (string, link.Address, error) {
	var addr link.Address
	cidr := argv[3]
	value, prefix, found := strings.Cut(cidr, "/")
	if !found {
		return "", addr, fmt.Errorf("address %q carries no prefix length", cidr)
	}
	length, err := strconv.Atoi(prefix)
	if err != nil {
		return "", addr, err
	}
	addr.Address = value
	addr.PrefixLength = length
	addr.Family = link.FamilyIPv4
	if strings.Contains(value, ":") {
		addr.Family = link.FamilyIPv6
	}

	name := ""
	for i := 4; i < len(argv); i++ {
		switch argv[i] {
		case "peer":
			i++
			addr.Peer = argv[i]
		case "dev":
			i++
			name = argv[i]
		}
	}
	if name == "" {
		return "", addr, fmt.Errorf("the address command names no device: %v", argv)
	}
	return name, addr, nil
}

// ------------------------------------------------------------------ harness

type harness struct {
	service  *Service
	repo     *Repo
	links    *link.Fake
	runner   *exec.FakeRunner
	systemd  *systemdSimulator
	store    *persist.Store
	settings *settings.Store
	dir      string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	database, err := db.Open(ctx, filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}

	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatalf("creating the settings store failed: %v", err)
	}

	systemdDir := filepath.Join(dir, "systemd")
	networkdDir := filepath.Join(dir, "networkd")
	for _, d := range []string{systemdDir, networkdDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("creating %s failed: %v", d, err)
		}
	}

	links := link.NewFakeWithHost()
	simulator := newSystemdSimulator(links, systemdDir)
	runner := exec.NewFakeRunner()
	runner.Handler = simulator.handle

	repo := NewRepo(database)
	persistStore := persist.NewStore(systemdDir, networkdDir, testSystemctlBin, runner)
	renderer := persist.NewRenderer(testIPBin, testModprobeBin, testPingBin)

	service := New(Deps{
		Repo:          repo,
		Links:         links,
		Runner:        runner,
		Renderer:      renderer,
		Store:         persistStore,
		Alloc:         alloc.New(repo, links, store),
		Validator:     validate.New(links, repo.ForValidation(), store, "/api/v1/reconcile/adopt"),
		Guard:         safety.New(links, systemdDir, networkdDir),
		Settings:      store,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		BinaryEnsurer: fakeBinaryEnsurer{},
		IPBin:         testIPBin,
		SystemctlBin:  testSystemctlBin,
	})

	return &harness{
		service: service, repo: repo, links: links, runner: runner,
		systemd: simulator, store: persistStore, settings: store, dir: dir,
	}
}

// fakeBinaryEnsurer stands in for the omnitun binary manager: the binary is
// already there, so creation never has to download anything. The unit the
// panel writes still points at the real binary path, which the systemd
// simulator models by its base name.
type fakeBinaryEnsurer struct{}

func (fakeBinaryEnsurer) Ensure(ctx context.Context) (string, error) {
	return "/var/lib/gre-panel/bin/omnitun", nil
}

// request builds a complete create request against the simulated host.
func request() Request {
	return Request{TunnelInput: validate.TunnelInput{
		LocalEndpoint:  "203.0.113.10",
		RemoteEndpoint: "198.51.100.20",
		IsEnabled:      true,
	}}
}

func (h *harness) unitPath(name string) string {
	return filepath.Join(h.dir, "systemd", persist.UnitName(name))
}

func (h *harness) mustCreate(t *testing.T, req Request) Result {
	t.Helper()
	result, err := h.service.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("creating the tunnel failed: %v", err)
	}
	return result
}

func (h *harness) setSetting(t *testing.T, key string, value any) {
	t.Helper()
	if _, err := h.settings.Update(context.Background(), map[string]any{key: value}, nil); err != nil {
		t.Fatalf("setting %s failed: %v", key, err)
	}
}

// interpretRelay models `gre-panel relay ...` by creating the TUN the relay
// owns, with the MTU and addresses it configures, and bringing it up. The
// token, the listen/dial choice and the port are the relay's business, not
// the kernel's, so they are parsed and ignored here — except that a missing
// token is a relay that refuses to start, which the simulator models as a
// failure.
func (s *systemdSimulator) interpretRelay(ctx context.Context, argv []string) error {
	if len(argv) < 2 || argv[1] != "relay" {
		return fmt.Errorf("the simulator does not run %v", argv)
	}
	var spec link.TunnelSpec
	spec.Kind = link.KindGREWSS
	var addresses []link.Address
	token := ""
	for i := 2; i < len(argv); i++ {
		switch argv[i] {
		case "--tun":
			i++
			spec.Name = argv[i]
		case "--key":
			i++
			n, err := strconv.ParseUint(argv[i], 10, 32)
			if err != nil {
				return err
			}
			key := uint32(n)
			spec.OKey = &key
		case "--in-key":
			i++
			n, err := strconv.ParseUint(argv[i], 10, 32)
			if err != nil {
				return err
			}
			key := uint32(n)
			spec.IKey = &key
		case "--token":
			i++
			token = argv[i]
		case "--mtu":
			i++
			mtu, err := strconv.Atoi(argv[i])
			if err != nil {
				return err
			}
			spec.Mtu = mtu
		case "--address":
			i++
			addr, err := parseRelayAddress(argv[i])
			if err != nil {
				return err
			}
			addresses = append(addresses, addr)
		case "--listen", "--dial":
			i++
		}
	}
	if spec.Name == "" {
		return fmt.Errorf("gre-panel relay without --tun")
	}
	if token == "" {
		return fmt.Errorf("gre-panel relay without a token")
	}
	if err := s.links.Create(ctx, spec); err != nil {
		return err
	}
	for _, addr := range addresses {
		if err := s.links.AddAddress(ctx, spec.Name, addr); err != nil {
			return err
		}
	}
	return s.links.SetUp(ctx, spec.Name)
}

// interpretOmni models `omnitun <transport> ...` by creating the TUN the
// binary owns, with the MTU and addresses it configures, and bringing it up.
// The key, the port, the listen/dial choice and the parallel-link count are
// the binary's business, not the kernel's, so they are parsed and ignored
// here — except that a missing key on a transport that needs one is a binary
// that refuses to start, which the simulator models as a failure.
func (s *systemdSimulator) interpretOmni(ctx context.Context, argv []string) error {
	if len(argv) < 2 || !link.OmniTransportValid(argv[1]) {
		return fmt.Errorf("the simulator does not run %v", argv)
	}
	transport := argv[1]
	var spec link.TunnelSpec
	spec.Kind = link.KindOmniTunnel
	spec.OmniTransport = transport
	var addresses []link.Address
	key := ""
	for i := 2; i < len(argv); i++ {
		switch argv[i] {
		case "-T":
			i++
			spec.Name = argv[i]
		case "-M":
			i++
			mtu, err := strconv.Atoi(argv[i])
			if err != nil {
				return err
			}
			spec.Mtu = mtu
		case "-A":
			i++
			addr, err := parseOmniAddress(argv[i], transport)
			if err != nil {
				return err
			}
			addresses = append(addresses, addr)
		case "-P":
			i++
			// The peer address is the other end of the same TUN link; the
			// simulator only needs the local end to bring the interface up.
		case "-k":
			i++
			key = argv[i]
		case "-L", "-R", "-p", "-N":
			i++
		case "-s", "-v":
		}
	}
	if spec.Name == "" {
		return fmt.Errorf("omnitun without -T")
	}
	if link.OmniTransportNeedsKey(transport) && key == "" {
		return fmt.Errorf("omnitun %s without a key", transport)
	}
	if err := s.links.Create(ctx, spec); err != nil {
		return err
	}
	for _, addr := range addresses {
		if err := s.links.AddAddress(ctx, spec.Name, addr); err != nil {
			return err
		}
	}
	return s.links.SetUp(ctx, spec.Name)
}

// parseOmniAddress parses one -A value: a bare TUN address, for example
// "172.17.1.1". The real binary rejects a CIDR here — it takes a bare IP —
// so the prefix is not on the command line. The panel's point-to-point pools
// are /30, which is what the allocator hands out, so the simulator uses
// that.
func parseOmniAddress(s string, transport string) (link.Address, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return link.Address{}, fmt.Errorf("invalid omnitun address: %s", s)
	}
	return link.Address{Address: ip.String(), PrefixLength: 30}, nil
}

// parseRelayAddress parses one --address value: "10.10.1.1/30", or
// "10.10.1.1 peer 10.10.1.2/32" for a single-address point-to-point link.
// In the peer form the local address carries no prefix of its own; the
// prefix comes from the peer's CIDR.
func parseRelayAddress(s string) (link.Address, error) {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return link.Address{}, fmt.Errorf("empty relay address")
	}
	if len(parts) == 3 && parts[1] == "peer" {
		ip := net.ParseIP(parts[0])
		if ip == nil {
			return link.Address{}, fmt.Errorf("invalid relay address: %s", parts[0])
		}
		peerIP, peerIPNet, err := net.ParseCIDR(parts[2])
		if err != nil {
			return link.Address{}, err
		}
		peerOnes, _ := peerIPNet.Mask.Size()
		return link.Address{Address: ip.String(), Peer: peerIP.String(), PrefixLength: peerOnes}, nil
	}
	ip, ipnet, err := net.ParseCIDR(parts[0])
	if err != nil {
		return link.Address{}, err
	}
	ones, _ := ipnet.Mask.Size()
	return link.Address{Address: ip.String(), PrefixLength: ones}, nil
}

// splitCommand splits a unit file's command line the way systemd does: on
// whitespace, except inside double quotes, where the quotes are removed and
// the content is one argument. A backslash inside quotes escapes the next
// character. This is what lets a --address value like "10.10.1.1 peer
// 10.10.1.2/30" survive the round trip through the unit file.
func splitCommand(s string) ([]string, error) {
	var argv []string
	var cur strings.Builder
	inQuotes := false
	escaped := false
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			if inQuotes {
				escaped = true
			} else {
				cur.WriteRune(r)
			}
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if inQuotes {
				cur.WriteRune(r)
			} else if cur.Len() > 0 {
				argv = append(argv, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	if cur.Len() > 0 {
		argv = append(argv, cur.String())
	}
	return argv, nil
}
