// EZTunnel transports, driven by the eztunnel binary. The fifteen are the
// ones eztunnel 0.9.14 runs: tcp, tcp6, ws, wss, http, https, xhttp, xhttps,
// kcp, fec-udp, fec-raw, fec-raw-gaming, tun, parallax and mirage. The panel
// runs the binary whole — it renders the JSON config, writes the systemd
// unit and manages the pairing — and never re-implements a transport, so
// the engine is EZTunnel itself. GRE and ESP are not here: EZTunnel has no
// GRE or ESP tunnel. GRE appears in it only as an outer packet shape of
// Mirage and FEC-RAW, and its encryption is Noise, not IPsec; the panel's
// own GRE and ESP tunnels stay separate types.
package link

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/blake2s"
)

// EZTunnel transports, in the order the form offers them.
const (
	EzTransportTCP          = "tcp"
	EzTransportTCP6         = "tcp6"
	EzTransportWS           = "ws"
	EzTransportWSS          = "wss"
	EzTransportHTTP         = "http"
	EzTransportHTTPS        = "https"
	EzTransportXHTTP        = "xhttp"
	EzTransportXHTTPS       = "xhttps"
	EzTransportKCP          = "kcp"
	EzTransportFECUDP       = "fec-udp"
	EzTransportFECRaw       = "fec-raw"
	EzTransportFECRawGaming = "fec-raw-gaming"
	EzTransportTUN          = "tun"
	EzTransportParallax     = "parallax"
	EzTransportMirage       = "mirage"
)

// EzTransports is every transport the panel can run through eztunnel.
var EzTransports = []string{
	EzTransportTCP, EzTransportTCP6, EzTransportWS, EzTransportWSS,
	EzTransportHTTP, EzTransportHTTPS, EzTransportXHTTP, EzTransportXHTTPS,
	EzTransportKCP, EzTransportFECUDP, EzTransportFECRaw, EzTransportFECRawGaming,
	EzTransportTUN, EzTransportParallax, EzTransportMirage,
}

// EzTransportValid reports whether the transport is one eztunnel runs.
func EzTransportValid(transport string) bool {
	for _, t := range EzTransports {
		if t == transport {
			return true
		}
	}
	return false
}

// EzTransportNeedsTLS reports whether the transport is a TLS carrier. TLS
// carriers always use tls_auto with the tunnel key in v1: no certificate
// files are managed by the panel.
func EzTransportNeedsTLS(transport string) bool {
	switch transport {
	case EzTransportHTTPS, EzTransportWSS, EzTransportXHTTPS:
		return true
	}
	return false
}

// EzTransportNeedsHTTPPath reports whether the transport takes an HTTP path
// (the HTTP and WebSocket families, including XHTTP).
func EzTransportNeedsHTTPPath(transport string) bool {
	switch transport {
	case EzTransportHTTP, EzTransportHTTPS, EzTransportWS, EzTransportWSS,
		EzTransportXHTTP, EzTransportXHTTPS:
		return true
	}
	return false
}

// EzTransportIsXHTTP reports whether the transport takes the nested xhttp
// block (mode and optional host override).
func EzTransportIsXHTTP(transport string) bool {
	return transport == EzTransportXHTTP || transport == EzTransportXHTTPS
}

// EzTransportNeedsFEC reports whether the transport takes the nested fec
// block (FEC tuning). The panel renders the defaults — MTU 1350, knock on
// — so no per-tunnel FEC field is stored.
func EzTransportNeedsFEC(transport string) bool {
	switch transport {
	case EzTransportFECUDP, EzTransportFECRaw, EzTransportFECRawGaming:
		return true
	}
	return false
}

// EzTransportNeedsRaw reports whether the transport takes the nested raw
// block (outer packet profile and the real peer). Raw carriers use one
// peer and connection pool one.
func EzTransportNeedsRaw(transport string) bool {
	switch transport {
	case EzTransportFECRaw, EzTransportFECRawGaming, EzTransportTUN, EzTransportMirage:
		return true
	}
	return false
}

// EzTransportIsMirage reports whether the transport is the spoof carrier.
// Mirage is experimental and permission-gated: the spoof sources it sends
// from must come from a test the operator ran first, never invented.
func EzTransportIsMirage(transport string) bool { return transport == EzTransportMirage }

// EzTransportNeedsPort reports whether the transport carries a port. Every
// EZTunnel transport does — even the raw ones, whose L4 port is the data
// port — so the port is always asked from the operator, never defaulted.
func EzTransportNeedsPort(transport string) bool { return true }

// EzTransportIsIPv6 reports whether the transport is IPv6-only: tcp6 takes
// literal IPv6 endpoints at both ends.
func EzTransportIsIPv6(transport string) bool { return transport == EzTransportTCP6 }

// EzXHTTPModes is every XHTTP mode the panel offers.
var EzXHTTPModes = []string{"auto", "stream-up", "packet-up"}

// EzXHTTPModeValid reports whether the mode is one XHTTP accepts.
func EzXHTTPModeValid(mode string) bool {
	for _, m := range EzXHTTPModes {
		if m == mode {
			return true
		}
	}
	return false
}

// EzRawProfiles is every outer packet profile a raw carrier takes.
var EzRawProfiles = []string{"tcp", "udp", "icmp", "gre", "ipip", "raw", "dns"}

// EzRawProfileValid reports whether the profile is one a raw carrier takes.
func EzRawProfileValid(profile string) bool {
	for _, p := range EzRawProfiles {
		if p == profile {
			return true
		}
	}
	return false
}

// EzMirageProfiles is every directional profile Mirage takes. The profile
// is the outer packet shape per direction, not a tunnel type: GRE here is
// a packet shape, not the panel's GRE tunnel.
var EzMirageProfiles = []string{"tcp", "udp", "icmp", "icmpv6", "gre", "ipip", "bip"}

// EzMirageProfileValid reports whether the profile is one Mirage takes.
func EzMirageProfileValid(profile string) bool {
	for _, p := range EzMirageProfiles {
		if p == profile {
			return true
		}
	}
	return false
}

// EzModeServer is the side that serves (listens); EzModeClient is the side
// that connects. Side A is always the server, side B always the client, so
// server_dials stays false: the foreign side dials the Iran side, which is
// the panel's reverse-tunnel direction.
const (
	EzModeServer = "server"
	EzModeClient = "client"
)

// EzDefaultMtu is the inner MTU eztunnel is run with. 1400 is eztunnel's
// own TUN default.
const EzDefaultMtu = 1400

// EzDefaultHttpPath is the HTTP path of the HTTP and WebSocket carriers.
// /tunnel is eztunnel's own default, and both ends must agree.
const EzDefaultHttpPath = "/tunnel"

// EzDefaultXHTTPMode is the XHTTP mode when the operator picks none: auto
// lets the two ends negotiate.
const EzDefaultXHTTPMode = "auto"

// EzDefaultRawInterface is the interface a raw carrier binds to when the
// operator gives none. eth0 is the usual name; the operator corrects it
// when the server names it differently.
const EzDefaultRawInterface = "eth0"

// EzFecMtu is the MTU of the FEC stream wrapper. 1350 is eztunnel's own
// default.
const EzFecMtu = 1350

// EzKeyAlphabet is the tunnel-key alphabet: Crockford base32 without u, and
// without the look-alikes i, l and o. A key is 24 random symbols from it
// plus one check symbol, written in five groups of five.
const EzKeyAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

const ezKeyDataSymbols = 24
const ezKeyGroup = 5

// ezKeyCheckSymbol returns the check symbol for 24 data symbols: the first
// byte of Blake2s-256 over the domain separator and the data, taken into
// the alphabet. It catches almost every copying mistake before a
// connection is attempted.
func ezKeyCheckSymbol(data string) byte {
	sum := blake2s.Sum256(append([]byte("eztunnel tunnel key check\x00"), data...))
	return EzKeyAlphabet[sum[0]&31]
}

// GenerateEzKey returns a fresh tunnel key in display form: five groups of
// five symbols joined by dashes.
func GenerateEzKey() (string, error) {
	buf := make([]byte, ezKeyDataSymbols)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	data := make([]byte, ezKeyDataSymbols)
	for i, b := range buf {
		data[i] = EzKeyAlphabet[b&31]
	}
	all := append(data, ezKeyCheckSymbol(string(data)))
	groups := make([]string, 0, 5)
	for i := 0; i < len(all); i += ezKeyGroup {
		groups = append(groups, string(all[i:i+ezKeyGroup]))
	}
	return strings.Join(groups, "-"), nil
}

// ParseEzKey validates a tunnel key as people type or paste it — case does
// not matter, dashes and spaces are ignored, o reads as 0 and i/l as 1 —
// and returns it in canonical display form. A key with the wrong length, a
// symbol outside the alphabet, or a check symbol that does not match is
// refused with the reason.
func ParseEzKey(key string) (string, error) {
	var symbols []byte
	for _, c := range key {
		switch c {
		case '-', ' ', '\t':
			continue
		case 'o', 'O':
			c = '0'
		case 'i', 'I', 'l', 'L':
			c = '1'
		default:
			c = unicode.ToLower(c)
		}
		if !strings.ContainsRune(EzKeyAlphabet, c) {
			return "", fmt.Errorf("an EZTunnel key contains only digits and the letters a-z (not u); found %q", string(c))
		}
		symbols = append(symbols, byte(c))
	}
	if len(symbols) != ezKeyDataSymbols+1 {
		return "", fmt.Errorf("an EZTunnel key has %d letters and digits in five groups of five; dashes and spaces are ignored (you entered %d letters and digits)", ezKeyDataSymbols+1, len(symbols))
	}
	data := string(symbols[:ezKeyDataSymbols])
	if symbols[ezKeyDataSymbols] != ezKeyCheckSymbol(data) {
		return "", fmt.Errorf("this EZTunnel key has a typo; copy it again from the other server")
	}
	all := append([]byte(data), symbols[ezKeyDataSymbols])
	groups := make([]string, 0, 5)
	for i := 0; i < len(all); i += ezKeyGroup {
		groups = append(groups, string(all[i:i+ezKeyGroup]))
	}
	return strings.Join(groups, "-"), nil
}

// EzBinaryVersion is the EZTunnel release the panel pins. The binary is
// downloaded from that release's tag, never from main, so a new EZTunnel
// release cannot change what this panel installs without the panel being
// updated to pin it.
const EzBinaryVersion = "v0.9.14"

// EzBinaryBase is where the eztunnel binary is downloaded from, with the
// release tag and the asset name appended.
const EzBinaryBase = "https://github.com/B3hnamR/EZTunnel/releases/download"

// EzBinaryAsset returns the release asset name for the given Go
// architecture. The release names its assets with the kernel naming
// (x86_64, aarch64), not Go's (amd64, arm64).
func EzBinaryAsset(arch string) (string, bool) {
	switch arch {
	case "amd64":
		return "eztunnel-0.9.14-linux-x86_64", true
	case "arm64":
		return "eztunnel-0.9.14-linux-aarch64", true
	}
	return "", false
}

// EzBinaryURL returns the download URL of the eztunnel binary for the given
// Go architecture (amd64 or arm64), from the pinned release.
func EzBinaryURL(arch string) (string, bool) {
	asset, ok := EzBinaryAsset(arch)
	if !ok {
		return "", false
	}
	return EzBinaryBase + "/" + EzBinaryVersion + "/" + asset, true
}

// EzBinaryChecksums is the SHA-256 of the eztunnel binary for each Go
// architecture, as published in EZTunnel v0.9.14's SHA256SUMS and verified
// by the panel against the downloaded binary. The binary is verified
// against this before it is installed; a download that does not match is
// refused, not installed.
var EzBinaryChecksums = map[string]string{
	"amd64": "a5ab711efa6b2a86f784a72686ed9101a4dd7f112f65e4e8d87ff15d6dfc67f9",
	"arm64": "8ab138d644cbfc316eea74f3d8dc451d9d431bbf68e9d6d30be2083f47b4d13d",
}

// EzBinaryName is the file name the binary is installed under, in the
// panel's data directory.
const EzBinaryName = "eztunnel"

// EzConfigPath returns the path of the JSON config the panel renders for a
// tunnel, under the panel's data directory. The file holds the tunnel key,
// so it is written 0600.
func EzConfigPath(dataDir, name string) string {
	return dataDir + "/eztunnel/" + name + ".json"
}

// EzArgs builds the eztunnel command line for a tunnel: the binary with the
// config file the panel rendered. The config carries everything — mode,
// transport, key, TUN addresses — so no flag is needed.
func EzArgs(binary, configPath string) []string {
	return []string{binary, "--config", configPath}
}

// ezJSON is the shape of an EZTunnel config file, in the order the binary
// reads it. Only the fields the panel sets are present: strict JSON
// rejects unknown settings, so nothing extra may appear. The maps, SOCKS5
// and allowed_targets of the manager's own configs are deliberately absent:
// the panel's tunnels are pure TUN tunnels, and port forwarding over the
// tunnel is not part of v1.
type ezJSON struct {
	Mode       string      `json:"mode"`
	TunnelKey  string      `json:"tunnel_key"`
	ServerDials bool       `json:"server_dials,omitempty"`
	Listeners  []ezEntry   `json:"listeners,omitempty"`
	Paths      []ezEntry   `json:"paths,omitempty"`
	Tun        *ezTun      `json:"tun,omitempty"`
}

type ezEntry struct {
	Addr            string   `json:"addr"`
	Transport       string   `json:"transport,omitempty"`
	TLSAuto         bool     `json:"tls_auto,omitempty"`
	HTTPPath        string   `json:"http_path,omitempty"`
	XHTTP           *ezXHTTP `json:"xhttp,omitempty"`
	FEC             *ezFEC   `json:"fec,omitempty"`
	Raw             *ezRaw   `json:"raw,omitempty"`
	ConnectionPool  *int     `json:"connection_pool,omitempty"`
}

type ezXHTTP struct {
	Mode string `json:"mode"`
	Host string `json:"host,omitempty"`
}

type ezFEC struct {
	Mtu   int  `json:"mtu"`
	Knock bool `json:"knock"`
}

type ezRaw struct {
	Profile              string    `json:"profile"`
	Interface            string    `json:"interface,omitempty"`
	LocalIP              string    `json:"local_ip,omitempty"`
	PeerIP               string    `json:"peer_ip"`
	L4Port               int       `json:"l4_port,omitempty"`
	Proto58Mode          *bool     `json:"proto58_mode,omitempty"`
	MirageAcknowledgement string   `json:"mirage_acknowledgement,omitempty"`
	Mirage               *ezMirage `json:"mirage,omitempty"`
}

type ezMirage struct {
	Uplink          string   `json:"uplink"`
	Downlink        string   `json:"downlink"`
	AllowRealSource bool     `json:"allow_real_source"`
	SourcePool      []string `json:"source_pool,omitempty"`
	ExpectedSources []string `json:"expected_sources,omitempty"`
	EchoMode        string   `json:"echo_mode,omitempty"`
	PaddingMax      int      `json:"padding_max,omitempty"`
	FakeTLS         bool     `json:"fake_tls,omitempty"`
}

type ezTun struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PeerAddress string `json:"peer_address"`
	Mtu         int    `json:"mtu"`
}

// EzConfigJSON renders the EZTunnel JSON config for one side of a tunnel.
// spec carries the tunnel (mode is server on side A, client on side B);
// addresses[0] carries this side's inner address and the peer's. The
// result is what the panel writes, 0600, to EzConfigPath. It is verified
// against the real binary with `eztunnel --config FILE --check` in the
// test suite, so a shape the binary refuses cannot ship.
func EzConfigJSON(spec TunnelSpec, addresses []Address) ([]byte, error) {
	if spec.EzKey == "" {
		return nil, fmt.Errorf("an EZTunnel tunnel needs a tunnel key")
	}
	if len(addresses) == 0 || addresses[0].Address == "" || addresses[0].Peer == "" {
		return nil, fmt.Errorf("an EZTunnel tunnel needs an inner address pair")
	}
	cfg := ezJSON{Mode: spec.EzMode, TunnelKey: spec.EzKey}
	if cfg.Mode != EzModeServer && cfg.Mode != EzModeClient {
		return nil, fmt.Errorf("an EZTunnel tunnel needs a mode of %q or %q", EzModeServer, EzModeClient)
	}
	entry := ezEntry{Transport: spec.EzTransport}
	if EzTransportNeedsTLS(spec.EzTransport) {
		entry.TLSAuto = true
	}
	if EzTransportNeedsHTTPPath(spec.EzTransport) {
		entry.HTTPPath = spec.EzHttpPath
		if entry.HTTPPath == "" {
			entry.HTTPPath = EzDefaultHttpPath
		}
	}
	if EzTransportIsXHTTP(spec.EzTransport) {
		mode := spec.EzXhttpMode
		if mode == "" {
			mode = EzDefaultXHTTPMode
		}
		entry.XHTTP = &ezXHTTP{Mode: mode, Host: spec.EzXhttpHost}
	}
	if EzTransportNeedsFEC(spec.EzTransport) {
		entry.FEC = &ezFEC{Mtu: EzFecMtu, Knock: true}
	}
	if EzTransportNeedsRaw(spec.EzTransport) {
		raw := &ezRaw{
			Profile:   spec.EzRawProfile,
			Interface: spec.EzRawInterface,
			LocalIP:   spec.Local,
			PeerIP:    spec.Remote,
			L4Port:    spec.EzPort,
		}
		if raw.Interface == "" {
			raw.Interface = EzDefaultRawInterface
		}
		if EzTransportIsMirage(spec.EzTransport) {
			raw.MirageAcknowledgement = "experimental-v2"
			raw.Mirage = &ezMirage{
				Uplink:          spec.EzMirageUplink,
				Downlink:        spec.EzMirageDownlink,
				AllowRealSource: true,
				SourcePool:      spec.EzSpoofSources,
				ExpectedSources: spec.EzMirageExpected,
				EchoMode:        "replies",
			}
		} else {
			off := false
			raw.Proto58Mode = &off
		}
		entry.Raw = raw
	}
	if cfg.Mode == EzModeServer {
		if EzTransportIsIPv6(spec.EzTransport) {
			entry.Addr = "[::]:" + strconv.Itoa(spec.EzPort)
		} else if EzTransportNeedsRaw(spec.EzTransport) {
			entry.Addr = joinHostPort(spec.Local, spec.EzPort)
		} else {
			entry.Addr = "0.0.0.0:" + strconv.Itoa(spec.EzPort)
		}
		cfg.Listeners = []ezEntry{entry}
	} else {
		pool := 1
		entry.ConnectionPool = &pool
		entry.Addr = joinHostPort(spec.Remote, spec.EzPort)
		cfg.Paths = []ezEntry{entry}
	}
	cfg.Tun = &ezTun{
		Name:        spec.Name,
		Address:     addresses[0].Address,
		PeerAddress: addresses[0].Peer,
		Mtu:         spec.Mtu,
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// EzConfig is the recoverable content of an EZTunnel JSON config file: the
// fields the panel needs to re-adopt a tunnel it once wrote, without
// asking the operator to retype them. The key is included because the
// panel wrote this file itself (0600) and the tunnel keeps working with
// the key it already has; a config whose key does not parse is not
// trusted at all. The TUN block is included because it is what the
// systemd simulator reads back to model the binary starting.
type EzConfig struct {
	Mode           string
	Key            string
	Transport      string
	Port           int
	HttpPath       string
	XhttpMode      string
	XhttpHost      string
	RawProfile     string
	RawInterface   string
	MirageUplink   string
	MirageDownlink string
	SpoofSources   []string
	MirageExpected []string
	TunName        string
	TunAddress     string
	TunPeerAddress string
	TunMtu         int
	// LocalEndpoint and RemoteEndpoint are the underlay addresses the
	// config names, when it names them at all: both for a raw carrier,
	// the peer only for a client, neither for a server. An empty one is
	// not a value the panel can guess.
	LocalEndpoint  string
	RemoteEndpoint string
}

// ParseEzConfig reads back a config EzConfigJSON wrote. It returns an error
// for anything it cannot make sense of — a missing entry, an unknown
// transport, a mode that is neither server nor client, a key that does
// not parse — so the caller can treat the file as absent rather than
// adopt a tunnel with settings nobody can vouch for.
func ParseEzConfig(data []byte) (EzConfig, error) {
	var cfg ezJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return EzConfig{}, fmt.Errorf("the EZTunnel config is not valid JSON: %w", err)
	}
	if cfg.Mode != EzModeServer && cfg.Mode != EzModeClient {
		return EzConfig{}, fmt.Errorf("the EZTunnel config names mode %q, not %q or %q", cfg.Mode, EzModeServer, EzModeClient)
	}
	if _, err := ParseEzKey(cfg.TunnelKey); err != nil {
		return EzConfig{}, fmt.Errorf("the EZTunnel config carries a tunnel key the panel cannot parse")
	}
	var entry ezEntry
	switch cfg.Mode {
	case EzModeServer:
		if len(cfg.Listeners) == 0 {
			return EzConfig{}, fmt.Errorf("the EZTunnel config has no listener")
		}
		entry = cfg.Listeners[0]
	default:
		if len(cfg.Paths) == 0 {
			return EzConfig{}, fmt.Errorf("the EZTunnel config has no path")
		}
		entry = cfg.Paths[0]
	}
	if !EzTransportValid(entry.Transport) {
		return EzConfig{}, fmt.Errorf("the EZTunnel config names transport %q, which the panel does not know", entry.Transport)
	}
	out := EzConfig{
		Mode:      cfg.Mode,
		Key:       cfg.TunnelKey,
		Transport: entry.Transport,
		HttpPath:  entry.HTTPPath,
	}
	if cfg.Tun != nil {
		out.TunName = cfg.Tun.Name
		out.TunAddress = cfg.Tun.Address
		out.TunPeerAddress = cfg.Tun.PeerAddress
		out.TunMtu = cfg.Tun.Mtu
	}
	// The endpoints are what the config holds, and only what it holds. A
	// raw carrier names both ends outright in its raw block. A client names
	// the peer in its path address. A server names neither: it listens on
	// 0.0.0.0 or [::], so the local endpoint is the host's own address
	// and the peer is whoever dials in — neither is in the file, and the
	// adoption leaves them empty rather than inventing them.
	if entry.Raw != nil {
		out.LocalEndpoint = entry.Raw.LocalIP
		out.RemoteEndpoint = entry.Raw.PeerIP
	} else if cfg.Mode == EzModeClient {
		if host, _, err := net.SplitHostPort(entry.Addr); err == nil {
			out.RemoteEndpoint = host
		}
	}
	// The port lives in the raw block for raw carriers and in the address
	// for every other transport; both are written by EzConfigJSON, so
	// either one is the port the operator entered.
	if entry.Raw != nil {
		out.Port = entry.Raw.L4Port
		out.RawProfile = entry.Raw.Profile
		if entry.Raw.Interface != "" {
			out.RawInterface = entry.Raw.Interface
		}
		if entry.Raw.Mirage != nil {
			out.MirageUplink = entry.Raw.Mirage.Uplink
			out.MirageDownlink = entry.Raw.Mirage.Downlink
			out.SpoofSources = entry.Raw.Mirage.SourcePool
			out.MirageExpected = entry.Raw.Mirage.ExpectedSources
		}
	}
	if out.Port == 0 {
		_, port, err := net.SplitHostPort(entry.Addr)
		if err != nil {
			return EzConfig{}, fmt.Errorf("the EZTunnel config names address %q, which has no port", entry.Addr)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 {
			return EzConfig{}, fmt.Errorf("the EZTunnel config names address %q, which has no port", entry.Addr)
		}
		out.Port = p
	}
	if entry.XHTTP != nil {
		out.XhttpMode = entry.XHTTP.Mode
		out.XhttpHost = entry.XHTTP.Host
	}
	return out, nil
}

// joinHostPort renders an IP and a port as an address, bracketing IPv6
// literals the way EZTunnel's config expects.
func joinHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}
