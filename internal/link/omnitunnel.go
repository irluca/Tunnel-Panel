package link

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

// OmniTunnel transports, driven by the omnitun core binary. The five are the
// ones omnitun itself runs: udp, tcp, mux, ws and icmp. stripe and ackless
// run on their own engines (omnistripe, omniackless) and hysteria on the
// bundled Hysteria2 binary, so they are not here; gre, fou and vxlan are
// kernel tunnels the panel already has or does not need.
const (
	OmniTransportUDP  = "udp"
	OmniTransportTCP  = "tcp"
	OmniTransportMUX  = "mux"
	OmniTransportWS   = "ws"
	OmniTransportICMP = "icmp"
)

// OmniTransports is every transport the panel can run through omnitun, in the
// order the form offers them.
var OmniTransports = []string{OmniTransportUDP, OmniTransportTCP, OmniTransportMUX, OmniTransportWS, OmniTransportICMP}

// OmniTransportValid reports whether the transport is one omnitun runs.
func OmniTransportValid(transport string) bool {
	for _, t := range OmniTransports {
		if t == transport {
			return true
		}
	}
	return false
}

// OmniTransportNeedsPort reports whether the transport carries a port. icmp
// has none — ICMP has no port — so a port for it is refused, not ignored.
func OmniTransportNeedsPort(transport string) bool { return transport != OmniTransportICMP }

// OmniTransportNeedsKey reports whether the transport carries a pre-shared
// key. icmp has none.
func OmniTransportNeedsKey(transport string) bool { return transport != OmniTransportICMP }

// OmniTransportHasServer reports whether the transport distinguishes a
// listening side from a dialing one. udp is symmetric: both ends run the
// same command, each pointing at the other.
func OmniTransportHasServer(transport string) bool { return transport != OmniTransportUDP }

// OmniTransportHasConns reports whether the transport takes a parallel-link
// count (-N). Only mux and ws do.
func OmniTransportHasConns(transport string) bool {
	return transport == OmniTransportMUX || transport == OmniTransportWS
}

// OmniModeListen is the side that serves (listens); OmniModeDial is the side
// that connects. udp is symmetric and ignores the mode.
const (
	OmniModeListen = "listen"
	OmniModeDial   = "dial"
)

// OmniDefaultMtu is the inner MTU omnitun is run with. 1400 is the value
// OmniTunnel's own manager passes.
const OmniDefaultMtu = 1400

// OmniDefaultConns is the parallel-link count for mux and ws. 8 is
// omnitun's own default, and 32 is its maximum.
const (
	OmniDefaultConns = 8
	OmniMaxConns     = 32
)

// OmniKeyBytes is the length of the pre-shared key, in bytes (hex-encoded to
// twice that many characters). 32 bytes is 64 hex characters, which is what
// omnitun's -k takes.
const OmniKeyBytes = 32

// GenerateOmniKey returns a fresh pre-shared key: 32 random bytes, hex.
func GenerateOmniKey() (string, error) {
	key := make([]byte, OmniKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// ParseOmniKey validates a pre-shared key: 64 hexadecimal characters.
func ParseOmniKey(key string) error {
	if len(key) != 2*OmniKeyBytes {
		return fmt.Errorf("an OmniTunnel key is %d hexadecimal characters", 2*OmniKeyBytes)
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("an OmniTunnel key is %d hexadecimal characters", 2*OmniKeyBytes)
	}
	return nil
}

// OmniBinaryVersion is the OmniTunnel release the panel pins. The binary is
// downloaded from that release's tag, never from main, so a new OmniTunnel
// release cannot change what this panel installs without the panel being
// updated to pin it.
const OmniBinaryVersion = "v2.9.17"

// OmniBinaryBase is where the omnitun binary is downloaded from, with the
// version and architecture appended.
const OmniBinaryBase = "https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel"

// OmniBinaryURL returns the download URL of the omnitun binary for the given
// architecture (amd64 or arm64), from the pinned release.
func OmniBinaryURL(arch string) string {
	return OmniBinaryBase + "/" + OmniBinaryVersion + "/bin/omnitun-" + arch
}

// OmniBinaryChecksums is the SHA-256 of the omnitun binary for each
// architecture, as published in OmniTunnel v2.9.17. The binary is verified
// against this before it is installed; a download that does not match is
// refused, not installed. OmniTunnel publishes no checksum file of its own,
// so the panel pins the values it verified itself.
var OmniBinaryChecksums = map[string]string{
	"amd64": "ed9c5652aecb5cc234da3bedd77e169f47753b704d5be04ea63bd1f813fd5078",
	"arm64": "3b3f030f965e1d7c6e241cfdee4908ba10a89f1fc66f54a0f008c5c2378edbe1",
}

// OmniBinaryName is the file name the binary is installed under, in the
// panel's data directory.
const OmniBinaryName = "omnitun"

// OmniArgs builds the omnitun command line for a tunnel. binary is the path
// to the omnitun binary; spec carries the tunnel. The flags follow omnitun
// 2.3.0's own usage, verified against the binary: udp takes no -s and no -N,
// tcp takes -s but no -N, mux and ws take -s and -N, icmp takes neither a
// port nor a key. server is whether this end listens; udp ignores it. The
// first address is the tunnel's own address (-A) and its peer is the far
// end's (-P).
func OmniArgs(binary string, spec TunnelSpec, addresses []Address) []string {
	args := []string{binary, spec.OmniTransport}
	args = append(args, "-L", spec.Local)
	args = append(args, "-R", spec.Remote)
	if len(addresses) > 0 {
		args = append(args, "-A", addresses[0].Address)
		if addresses[0].Peer != "" {
			args = append(args, "-P", addresses[0].Peer)
		}
	}
	if OmniTransportNeedsPort(spec.OmniTransport) {
		args = append(args, "-p", strconv.Itoa(spec.OmniPort))
	}
	if OmniTransportNeedsKey(spec.OmniTransport) {
		args = append(args, "-k", spec.OmniKey)
	}
	if OmniTransportHasServer(spec.OmniTransport) && spec.OmniMode == OmniModeListen {
		args = append(args, "-s")
	}
	if OmniTransportHasConns(spec.OmniTransport) && spec.OmniConns > 0 {
		args = append(args, "-N", strconv.Itoa(spec.OmniConns))
	}
	args = append(args, "-T", spec.Name)
	if spec.Mtu > 0 {
		args = append(args, "-M", strconv.Itoa(spec.Mtu))
	}
	return args
}
