package link

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/exec"
)

func u32(v uint32) *uint32 { return &v }

func TestKeyDottedRoundTrip(t *testing.T) {
	// The verified pair from §2: iproute2 prints the integer key this way.
	if got := KeyToDotted(2749365187); got != "163.223.251.195" {
		t.Fatalf("KeyToDotted(2749365187) = %q, want 163.223.251.195", got)
	}
	got, err := KeyFromDotted("163.223.251.195")
	if err != nil || got != 2749365187 {
		t.Fatalf("KeyFromDotted = %d, %v; want 2749365187", got, err)
	}

	for _, key := range []uint32{0, 1, 255, 256, 65535, 2749365187, 4294967295} {
		back, err := KeyFromDotted(KeyToDotted(key))
		if err != nil || back != key {
			t.Fatalf("round trip of %d gave %d, %v", key, back, err)
		}
	}
}

func TestKeyFromDottedAcceptsIntegersAndRejectsRubbish(t *testing.T) {
	if got, err := KeyFromDotted("2749365187"); err != nil || got != 2749365187 {
		t.Fatalf("plain integer form = %d, %v", got, err)
	}
	for _, bad := range []string{"", "not-a-key", "1.2.3", "1.2.3.4.5", "4294967296", "300.1.1.1"} {
		if _, err := KeyFromDotted(bad); err == nil {
			t.Fatalf("%q was accepted as a GRE key", bad)
		}
	}
}

func TestCreateArgsMatchesTheDocumentedForm(t *testing.T) {
	spec := TunnelSpec{
		Name: "gre-a-7", Kind: KindGRE, Local: "203.0.113.10", Remote: "198.51.100.20",
		Ttl: 255, Tos: "inherit", IKey: u32(2749365187), OKey: u32(2749365187),
	}
	got := strings.Join(CreateArgs("/sbin/ip", spec), " ")
	// The type of service and path MTU discovery are stated even at their
	// defaults, because iproute2 and the netlink path disagree about what those
	// defaults are and the two must produce the same link.
	want := "/sbin/ip link add name gre-a-7 type gre local 203.0.113.10 remote 198.51.100.20 " +
		"ttl 255 tos inherit ikey 2749365187 okey 2749365187 nopmtudisc"
	if got != want {
		t.Fatalf("create argv\n got: %s\nwant: %s", got, want)
	}
}

func TestCreateArgsCarriesEveryOptionalAttribute(t *testing.T) {
	spec := TunnelSpec{
		Name: "gre-b-2", Kind: KindGRE, Local: "203.0.113.10", Remote: "198.51.100.20",
		Ttl: 0, Tos: "0x10", IKey: u32(7), OKey: u32(8),
		HasInputChecksum: true, HasOutputChecksum: true,
		HasInputSequence: true, HasOutputSequence: true,
		IsPathMtuDiscovery: true, IsIgnoreDf: true,
		FwMark: u32(42), BindDevice: "eth0",
	}
	got := strings.Join(CreateArgs("/sbin/ip", spec), " ")
	want := "/sbin/ip link add name gre-b-2 type gre local 203.0.113.10 remote 198.51.100.20 " +
		"ttl inherit tos 0x10 ikey 7 okey 8 icsum ocsum iseq oseq pmtudisc ignore-df fwmark 42 dev eth0"
	if got != want {
		t.Fatalf("create argv\n got: %s\nwant: %s", got, want)
	}
}

func TestCreateArgsForIPv6UsesHopLimit(t *testing.T) {
	hop := 64
	limit := 4
	spec := TunnelSpec{
		Name: "gre6-a-1", Kind: KindIP6GRE, Local: "2001:db8::1", Remote: "2001:db8::2",
		Ttl: 255, HopLimit: &hop, EncapLimit: &limit, FlowLabel: "0x12345",
	}
	got := strings.Join(CreateArgs("/sbin/ip", spec), " ")
	want := "/sbin/ip link add name gre6-a-1 type ip6gre local 2001:db8::1 remote 2001:db8::2 " +
		"hoplimit 64 tos inherit encaplimit 4 flowlabel 0x12345"
	if got != want {
		t.Fatalf("create argv\n got: %s\nwant: %s", got, want)
	}
}

func TestAddressArgs(t *testing.T) {
	addr := Address{Address: "172.17.7.1", PrefixLength: 30, Family: FamilyIPv4}
	if got := strings.Join(AddAddressArgs("/sbin/ip", "gre-a-7", addr), " "); got !=
		"/sbin/ip addr add 172.17.7.1/30 dev gre-a-7" {
		t.Fatalf("add address argv = %q", got)
	}
	// On a /30 the peer already sits inside the subnet, so naming it would
	// produce a host address plus a route instead of a connected subnet — a
	// different layout from the one the tunnels being adopted already have.
	addr.Peer = "172.17.7.2"
	if got := strings.Join(DelAddressArgs("/sbin/ip", "gre-a-7", addr), " "); got !=
		"/sbin/ip addr del 172.17.7.1/30 dev gre-a-7" {
		t.Fatalf("del address argv = %q", got)
	}

	// A host address genuinely needs the peer spelled out.
	host := Address{Address: "172.17.7.1", PrefixLength: 32, Peer: "172.17.7.2", Family: FamilyIPv4}
	if !host.NeedsExplicitPeer() {
		t.Fatal("a /32 assignment needs its peer named")
	}
	if got := strings.Join(AddAddressArgs("/sbin/ip", "gre-a-7", host), " "); got !=
		"/sbin/ip addr add 172.17.7.1/32 peer 172.17.7.2 dev gre-a-7" {
		t.Fatalf("host address argv = %q", got)
	}
	if (Address{Address: "fd00::1", PrefixLength: 127, Peer: "fd00::", Family: FamilyIPv6}).NeedsExplicitPeer() {
		t.Fatal("a /127 assignment carries its peer in the subnet")
	}
}

// The fixture is the output shape verified on the real server in §2, including
// the dotted-quad keys and the operational state UNKNOWN of a healthy tunnel.
const verifiedLinkJSON = `[{"ifindex":42,"ifname":"gre-a-42","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],
  "mtu":1472,"operstate":"UNKNOWN","link_type":"gre","txqlen":1000,
  "remote":"185.199.108.153","local":"203.0.113.10","ttl":255,
  "ikey":"163.223.251.195","okey":"163.223.251.195",
  "stats64":{"rx":{"bytes":100,"packets":2,"errors":0,"dropped":0},
             "tx":{"bytes":200,"packets":4,"errors":0,"dropped":1}}}]`

func TestParseLinksFlattenedShape(t *testing.T) {
	links, err := parseLinks([]byte(verifiedLinkJSON))
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("parsed %d links, want 1", len(links))
	}
	l := links[0]
	if l.Name != "gre-a-42" || l.Kind != KindGRE || l.MTU != 1472 {
		t.Fatalf("link decoded wrongly: %+v", l)
	}
	if l.OperState != "UNKNOWN" {
		t.Fatalf("operational state = %q; a healthy GRE tunnel reports UNKNOWN", l.OperState)
	}
	if !l.IsUp || !l.IsLowerUp {
		t.Fatal("UP and LOWER_UP must be derived from the flag list")
	}
	if l.Tunnel == nil {
		t.Fatal("tunnel attributes were not decoded")
	}
	if l.Tunnel.Local != "203.0.113.10" || l.Tunnel.Remote != "185.199.108.153" || l.Tunnel.Ttl != 255 {
		t.Fatalf("tunnel attributes decoded wrongly: %+v", l.Tunnel)
	}
	if l.Tunnel.IKey == nil || *l.Tunnel.IKey != 2749365187 {
		t.Fatalf("ikey = %v, want the integer 2749365187", l.Tunnel.IKey)
	}
	if l.Tunnel.OKey == nil || *l.Tunnel.OKey != 2749365187 {
		t.Fatalf("okey = %v, want the integer 2749365187", l.Tunnel.OKey)
	}
	if l.Statistics == nil || l.Statistics.RxBytes != 100 || l.Statistics.TxDropped != 1 {
		t.Fatalf("statistics decoded wrongly: %+v", l.Statistics)
	}
}

func TestParseLinksNestedShape(t *testing.T) {
	const nested = `[{"ifindex":3,"ifname":"gre-b-1","flags":["POINTOPOINT","UP"],"mtu":1400,
	  "operstate":"UNKNOWN","link_type":"gre",
	  "linkinfo":{"info_kind":"gre","info_data":{"remote":"198.51.100.1","local":"203.0.113.1",
	    "ttl":"inherit","ikey":"0.0.0.7","icsum":true,"oseq":true,"pmtudisc":false}}},
	 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback"},
	 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","UP"],"mtu":1500,"operstate":"UP","link_type":"ether"},
	 {"ifindex":4,"ifname":"br0","flags":["BROADCAST","UP"],"mtu":1500,"operstate":"UP","link_type":"ether",
	  "linkinfo":{"info_kind":"bridge"}}]`

	links, err := parseLinks([]byte(nested))
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	byName := ByName(links)

	gre := byName["gre-b-1"]
	if gre.Tunnel == nil || gre.Tunnel.Ttl != 0 {
		t.Fatalf(`ttl "inherit" must decode to 0: %+v`, gre.Tunnel)
	}
	if gre.Tunnel.IKey == nil || *gre.Tunnel.IKey != 7 {
		t.Fatalf("ikey = %v, want 7", gre.Tunnel.IKey)
	}
	if !gre.Tunnel.HasInputChecksum || gre.Tunnel.HasOutputChecksum {
		t.Fatalf("checksum flags decoded wrongly: %+v", gre.Tunnel)
	}
	if !gre.Tunnel.HasOutputSequence || gre.Tunnel.HasInputSequence {
		t.Fatalf("sequence flags decoded wrongly: %+v", gre.Tunnel)
	}
	if gre.Tunnel.IsPathMtuDiscovery {
		t.Fatal("pmtudisc false must decode as disabled")
	}

	if !byName["lo"].IsLoopback() || byName["lo"].IsPhysical() {
		t.Fatal("the loopback interface was classified wrongly")
	}
	if !byName["eth0"].IsPhysical() {
		t.Fatal("a plain NIC must be classified as physical")
	}
	if !byName["br0"].IsBridge() || byName["br0"].IsPhysical() {
		t.Fatal("a bridge was classified wrongly")
	}
	if !byName["gre-b-1"].IsTunnel() {
		t.Fatal("a GRE interface must be classified as a tunnel")
	}
}

func TestParseAddressesAndRoutes(t *testing.T) {
	const addrJSON = `[{"ifname":"gre-a-1","addr_info":[
	  {"family":"inet","local":"172.17.1.1","address":"172.17.1.2","prefixlen":30,"scope":"global"},
	  {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]`
	byName, err := parseAddresses([]byte(addrJSON))
	if err != nil {
		t.Fatalf("parsing addresses failed: %v", err)
	}
	addrs := byName["gre-a-1"]
	if len(addrs) != 2 {
		t.Fatalf("parsed %d addresses, want 2", len(addrs))
	}
	if addrs[0].Address != "172.17.1.1" || addrs[0].PrefixLength != 30 || addrs[0].Peer != "172.17.1.2" {
		t.Fatalf("point-to-point address decoded wrongly: %+v", addrs[0])
	}
	if addrs[1].Family != FamilyIPv6 {
		t.Fatalf("family = %q, want ipv6", addrs[1].Family)
	}

	const routeJSON = `[{"dst":"default","gateway":"203.0.113.1","dev":"eth0","protocol":"static","metric":100},
	  {"dst":"172.17.1.0/30","dev":"gre-a-1","protocol":"kernel","prefsrc":"172.17.1.1"}]`
	routes, err := parseRoutes([]byte(routeJSON))
	if err != nil {
		t.Fatalf("parsing routes failed: %v", err)
	}
	if len(routes) != 2 || !routes[0].IsDefault || routes[1].IsDefault {
		t.Fatalf("routes decoded wrongly: %+v", routes)
	}
	if devices := DefaultRouteDevices(routes); !devices["eth0"] || len(devices) != 1 {
		t.Fatalf("default route devices = %v", devices)
	}
}

func TestFakeModelsKernelBehaviour(t *testing.T) {
	ctx := context.Background()
	f := NewFakeWithHost()

	spec := TunnelSpec{
		Name: "gre-a-1", Kind: KindGRE, Local: "203.0.113.10", Remote: "198.51.100.20",
		Ttl: 255, Mtu: 1472, IKey: u32(2749365187), OKey: u32(2749365187),
	}
	if err := f.Create(ctx, spec); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	created, err := f.Get(ctx, "gre-a-1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if created.IsUp {
		t.Fatal("a freshly created tunnel must be down until it is brought up")
	}

	if err := f.AddAddress(ctx, "gre-a-1", Address{Address: "172.17.1.1", PrefixLength: 30, Family: FamilyIPv4}); err != nil {
		t.Fatalf("adding an address failed: %v", err)
	}
	if err := f.SetUp(ctx, "gre-a-1"); err != nil {
		t.Fatalf("bringing the tunnel up failed: %v", err)
	}

	up, _ := f.Get(ctx, "gre-a-1")
	if !up.IsUp || !up.IsLowerUp {
		t.Fatal("UP and LOWER_UP must be set after bringing the tunnel up")
	}
	if up.OperState != "UNKNOWN" {
		t.Fatalf("operational state = %q; a healthy GRE tunnel reports UNKNOWN", up.OperState)
	}
	if !up.HasAddress(Address{Address: "172.17.1.1", PrefixLength: 30}) {
		t.Fatal("the address was not recorded")
	}

	// Creating the same interface twice must be refused, and deleting one that
	// is already gone must not be.
	if err := f.Create(ctx, spec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create error = %v, want ErrExists", err)
	}
	if err := f.Delete(ctx, "gre-a-1"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if err := f.Delete(ctx, "gre-a-1"); err != nil {
		t.Fatalf("deleting an absent interface must succeed, got %v", err)
	}
	if _, err := f.Get(ctx, "gre-a-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestFakePublishesEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := NewFake()
	events, err := f.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe failed: %v", err)
	}
	if err := f.Create(ctx, TunnelSpec{Name: "gre-a-1", Kind: KindGRE}); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	ev := <-events
	if ev.Kind != EventAdded || ev.Link.Name != "gre-a-1" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestFallbackRetriesOnUnsupported(t *testing.T) {
	ctx := context.Background()
	primary := NewFake()
	primary.UnsupportedKinds[KindIP6GRE] = true
	secondary := NewFake()

	fb := NewFallback(primary, secondary)
	spec := TunnelSpec{Name: "gre6-a-1", Kind: KindIP6GRE, Local: "2001:db8::1", Remote: "2001:db8::2"}
	if err := fb.Create(ctx, spec); err != nil {
		t.Fatalf("the fallback did not serve an unsupported type: %v", err)
	}
	if _, err := secondary.Get(ctx, "gre6-a-1"); err != nil {
		t.Fatalf("the secondary manager did not create the tunnel: %v", err)
	}
	if _, err := primary.Get(ctx, "gre6-a-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the primary manager must not have created the tunnel")
	}

	// A plain failure is not retried: only "this manager cannot do that" is.
	primary.FailOn["create gre-a-2"] = errors.New("kernel said no")
	if err := fb.Create(ctx, TunnelSpec{Name: "gre-a-2", Kind: KindGRE}); err == nil {
		t.Fatal("a real failure must not be retried into a success")
	}
	if _, err := secondary.Get(ctx, "gre-a-2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a real failure must not fall through to the secondary manager")
	}
}

func TestFallbackForcedUsesTheSecondary(t *testing.T) {
	ctx := context.Background()
	primary, secondary := NewFake(), NewFake()
	fb := NewFallback(primary, secondary)
	fb.Forced = true

	if fb.Name() != ManagerFake {
		t.Fatalf("name = %q", fb.Name())
	}
	if err := fb.Create(ctx, TunnelSpec{Name: "gre-a-1", Kind: KindGRE}); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := secondary.Get(ctx, "gre-a-1"); err != nil {
		t.Fatalf("the forced manager was not used: %v", err)
	}
}

func TestIPCommandParsesThroughTheRunner(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Responses["/sbin/ip -j -d -s link show"] = exec.Result{Stdout: verifiedLinkJSON}
	runner.Responses["/sbin/ip -j addr show"] = exec.Result{
		Stdout: `[{"ifname":"gre-a-42","addr_info":[{"family":"inet","local":"172.17.42.1","address":"172.17.42.1","prefixlen":30,"scope":"global"}]}]`,
	}

	m := NewIPCommand("/sbin/ip", runner)
	links, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(links) != 1 || links[0].Name != "gre-a-42" {
		t.Fatalf("links = %+v", links)
	}
	if len(links[0].Addresses) != 1 || links[0].Addresses[0].Address != "172.17.42.1" {
		t.Fatalf("addresses = %+v", links[0].Addresses)
	}
	if links[0].Addresses[0].Peer != "" {
		t.Fatal("an ordinary assignment must not report a peer")
	}
}

func TestIPCommandTreatsAMissingDeviceAsDeleted(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Responses["/sbin/ip link del gre-gone"] = exec.Result{
		ExitCode: 1, Stderr: `Cannot find device "gre-gone"`,
	}
	runner.Errors["/sbin/ip link del gre-gone"] = errors.New("ip exited 1")

	m := NewIPCommand("/sbin/ip", runner)
	if err := m.Delete(context.Background(), "gre-gone"); err != nil {
		t.Fatalf("deleting an absent device must succeed, got %v", err)
	}
}

func TestIPCommandWithoutABinaryIsUnsupported(t *testing.T) {
	m := NewIPCommand("", exec.NewFakeRunner())
	if _, err := m.List(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if caps := m.Capabilities(); caps.Available {
		t.Fatal("a manager with no binary must report itself unavailable")
	}
}

func TestSelectPrefersTheFakeInDevelopmentMode(t *testing.T) {
	if got := Select(Options{DevMode: true, IPBin: "/sbin/ip"}).Name(); got != ManagerFake {
		t.Fatalf("development mode selected %q, want the fake", got)
	}
}

func TestMergeCapabilitiesAttributesEachType(t *testing.T) {
	primary := NewFake()
	primary.UnsupportedKinds[KindIP6GRE] = true
	primary.UnsupportedKinds[KindIP6GRETAP] = true
	secondary := NewIPCommand("/sbin/ip", exec.NewFakeRunner())

	merged := MergeCapabilities(primary, secondary)
	if !merged[KindGRE].Supported || merged[KindGRE].Manager != ManagerFake {
		t.Fatalf("GRE support = %+v", merged[KindGRE])
	}
	if !merged[KindIP6GRE].Supported || merged[KindIP6GRE].Manager != ManagerIP {
		t.Fatalf("IP6GRE must fall to the ip command: %+v", merged[KindIP6GRE])
	}
}

// ------------------------------------------------------------- ESP tunnels

func espTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := ParseEspKey("aabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatalf("the test ESP key must parse: %v", err)
	}
	return key
}

func espTestSpec(t *testing.T) TunnelSpec {
	t.Helper()
	return TunnelSpec{
		Name: "esp-a-1", Kind: KindESP, Local: "203.0.113.10", Remote: "198.51.100.20",
		Mtu: 1350, EspKey: espTestKey(t),
		EspSPIOut: 0x12345678, EspSPIIn: 0x87654321, EspIfID: 42,
	}
}

func TestCreateArgsForEsp(t *testing.T) {
	got := strings.Join(CreateArgs("/sbin/ip", espTestSpec(t)), " ")
	want := "/sbin/ip link add name esp-a-1 type xfrm if_id 42"
	if got != want {
		t.Fatalf("ESP create argv\n got: %s\nwant: %s", got, want)
	}
}

func TestXfrmStateAddArgs(t *testing.T) {
	spec := espTestSpec(t)
	key := "0xaabbccddeeff00112233445566778899aabbccdd"
	got := strings.Join(XfrmStateAddArgs("/sbin/ip", spec, true), " ")
	want := "/sbin/ip xfrm state add src 203.0.113.10 dst 198.51.100.20 proto esp " +
		"spi 0x12345678 mode transport aead rfc4106(gcm(aes)) " + key + " 128 replay-window 32 if_id 42"
	if got != want {
		t.Fatalf("outbound state argv\n got: %s\nwant: %s", got, want)
	}
	got = strings.Join(XfrmStateAddArgs("/sbin/ip", spec, false), " ")
	want = "/sbin/ip xfrm state add src 198.51.100.20 dst 203.0.113.10 proto esp " +
		"spi 0x87654321 mode transport aead rfc4106(gcm(aes)) " + key + " 128 replay-window 32 if_id 42"
	if got != want {
		t.Fatalf("inbound state argv\n got: %s\nwant: %s", got, want)
	}
}

func TestXfrmPolicyArgs(t *testing.T) {
	spec := espTestSpec(t)
	got := strings.Join(XfrmPolicyAddArgs("/sbin/ip", spec, true), " ")
	want := "/sbin/ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir out " +
		"tmpl src 203.0.113.10 dst 198.51.100.20 proto esp spi 0x12345678 mode transport reqid 42 if_id 42"
	if got != want {
		t.Fatalf("outbound policy argv\n got: %s\nwant: %s", got, want)
	}
	got = strings.Join(XfrmPolicyAddArgs("/sbin/ip", spec, false), " ")
	want = "/sbin/ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir in " +
		"tmpl src 198.51.100.20 dst 203.0.113.10 proto esp spi 0x87654321 mode transport reqid 42 if_id 42"
	if got != want {
		t.Fatalf("inbound policy argv\n got: %s\nwant: %s", got, want)
	}
	got = strings.Join(XfrmPolicyDelArgs("/sbin/ip", spec, true), " ")
	want = "/sbin/ip xfrm policy del src 0.0.0.0/0 dst 0.0.0.0/0 dir out if_id 42"
	if got != want {
		t.Fatalf("policy delete argv\n got: %s\nwant: %s", got, want)
	}
}

func TestFakeEspCreateRecordsAssociations(t *testing.T) {
	f := NewFake()
	spec := espTestSpec(t)
	if err := f.Create(context.Background(), spec); err != nil {
		t.Fatalf("fake ESP create failed: %v", err)
	}
	got, err := f.Get(context.Background(), "esp-a-1")
	if err != nil {
		t.Fatalf("fake ESP get failed: %v", err)
	}
	if got.Kind != KindESP {
		t.Fatalf("fake link kind = %q, want %q", got.Kind, KindESP)
	}
	if got.Tunnel == nil || got.Tunnel.Esp == nil {
		t.Fatal("the fake did not record the ESP associations")
	}
	esp := got.Tunnel.Esp
	if esp.IfID != 42 {
		t.Fatalf("IfID = %d, want 42", esp.IfID)
	}
	if len(esp.SPIs) != 2 || esp.SPIs[0] != 0x12345678 || esp.SPIs[1] != 0x87654321 {
		t.Fatalf("SPIs = %v, want [0x12345678 0x87654321]", esp.SPIs)
	}
	if !esp.PoliciesPresent {
		t.Fatal("the fake must report both policies present")
	}
}

// The fixture is the shape `ip -j -d link show` reports for an xfrm
// interface: the kind in linkinfo, the identifier in its info_data.
const verifiedXfrmLinkJSON = `[{"ifindex":7,"ifname":"esp-a-1","flags":["POINTOPOINT","NOARP","UP"],` +
	`"mtu":1350,"operstate":"UNKNOWN","txqlen":1000,` +
	`"linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42}}}]`

func TestParseLinksXfrm(t *testing.T) {
	links, err := parseLinks([]byte(verifiedXfrmLinkJSON))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("links = %+v", links)
	}
	if links[0].Kind != KindESP {
		t.Fatalf("kind = %q, want %q", links[0].Kind, KindESP)
	}
	if links[0].Tunnel == nil || links[0].Tunnel.Esp == nil {
		t.Fatal("an xfrm interface must carry ESP attributes")
	}
	if links[0].Tunnel.Esp.IfID != 42 {
		t.Fatalf("IfID = %d, want 42", links[0].Tunnel.Esp.IfID)
	}
}

func TestIPCommandXfrmAttrs(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Responses["/sbin/ip -j -d -s link show"] = exec.Result{Stdout: verifiedXfrmLinkJSON}
	runner.Responses["/sbin/ip -j addr show"] = exec.Result{Stdout: `[]`}
	runner.Responses["/sbin/ip -j xfrm state"] = exec.Result{Stdout: `[
		{"src":"203.0.113.10","dst":"198.51.100.20","proto":"esp","spi":305419896,"reqid":42,"mode":"transport","if_id":42},
		{"src":"198.51.100.20","dst":"203.0.113.10","proto":"esp","spi":2271560481,"reqid":42,"mode":"transport","if_id":42}]`}
	runner.Responses["/sbin/ip -j xfrm policy"] = exec.Result{Stdout: `[
		{"src":"0.0.0.0/0","dst":"0.0.0.0/0","dir":"out","if_id":42},
		{"src":"0.0.0.0/0","dst":"0.0.0.0/0","dir":"in","if_id":42}]`}

	m := NewIPCommand("/sbin/ip", runner)
	links, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("links = %+v", links)
	}
	esp := links[0].Tunnel.Esp
	if esp == nil {
		t.Fatal("the list did not attach the XFRM facts")
	}
	if esp.IfID != 42 {
		t.Fatalf("IfID = %d, want 42", esp.IfID)
	}
	if len(esp.SPIs) != 2 || esp.SPIs[0] != 0x12345678 || esp.SPIs[1] != 0x87654321 {
		t.Fatalf("SPIs = %v, want [0x12345678 0x87654321]", esp.SPIs)
	}
	if !esp.PoliciesPresent {
		t.Fatal("both policies are present in the fixture, so PoliciesPresent must be true")
	}
}

func TestIPCommandEspCreateRunsTheWholeSequence(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Responses["/sbin/ip -j xfrm state"] = exec.Result{Stdout: `[]`}
	runner.Responses["/sbin/ip -j xfrm policy"] = exec.Result{Stdout: `[]`}

	m := NewIPCommand("/sbin/ip", runner)
	if err := m.Create(context.Background(), espTestSpec(t)); err != nil {
		t.Fatalf("ESP create failed: %v", err)
	}
	key := "0xaabbccddeeff00112233445566778899aabbccdd"
	want := []string{
		"/sbin/ip -j xfrm state",
		"/sbin/ip -j xfrm policy",
		"/sbin/ip link add name esp-a-1 type xfrm if_id 42",
		"/sbin/ip xfrm state add src 203.0.113.10 dst 198.51.100.20 proto esp spi 0x12345678 mode transport aead rfc4106(gcm(aes)) " + key + " 128 replay-window 32 if_id 42",
		"/sbin/ip xfrm state add src 198.51.100.20 dst 203.0.113.10 proto esp spi 0x87654321 mode transport aead rfc4106(gcm(aes)) " + key + " 128 replay-window 32 if_id 42",
		"/sbin/ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir out tmpl src 203.0.113.10 dst 198.51.100.20 proto esp spi 0x12345678 mode transport reqid 42 if_id 42",
		"/sbin/ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir in tmpl src 198.51.100.20 dst 203.0.113.10 proto esp spi 0x87654321 mode transport reqid 42 if_id 42",
	}
	if got := runner.CommandLines(); len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d:\n%v", len(got), len(want), got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("command %d\n got: %s\nwant: %s", i, got[i], want[i])
			}
		}
	}
}

func TestIPCommandEspCreateWithoutAKeyFailsBeforeAnyCommand(t *testing.T) {
	runner := exec.NewFakeRunner()
	spec := espTestSpec(t)
	spec.EspKey = nil
	m := NewIPCommand("/sbin/ip", runner)
	if err := m.Create(context.Background(), spec); err == nil {
		t.Fatal("an ESP tunnel with no key must not be created")
	}
	if got := runner.CommandLines(); len(got) != 0 {
		t.Fatalf("a rejected specification still ran %d commands: %v", len(got), got)
	}
}
