package link

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/drs/gre-panel/internal/i18n"
)

// ESP tunnel identity.
//
// An ESP tunnel is a kernel xfrm interface bound to a pair of manually keyed
// IPsec security associations: AES-128-GCM, no IKE, transport mode. The two
// ends never exchange the SPIs through a handshake, so the panel derives them
// deterministically from the tunnel's stable identity instead. Both ends
// compute the same pair, because the derivation orders the endpoints
// canonically: the SPI for traffic from the canonically first endpoint to
// the second is one value, and the SPI for the reverse direction is another,
// and each side knows which of the two is its outbound one.
//
// The identity includes the inner address pair, not just the outer
// endpoints, because two ESP tunnels between the same two hosts must still
// get different SPIs — the kernel identifies a security association by
// (destination, protocol, SPI), and the inner subnets are what tell two
// tunnels between one pair of hosts apart. A tunnel with no inner addresses
// yet falls back to the outer endpoints alone.
//
// The interface identifier is purely local — it binds this host's states and
// policies to its own interface — so it is derived from the local view
// (endpoints plus interface name) and need not agree between the two ends.

// EspAeadName is the AEAD algorithm of an ESP security association.
const EspAeadName = "rfc4106(gcm(aes))"

// EspAeadKeyBytes is the key length the kernel expects for AES-128-GCM: 16
// bytes of key plus 4 bytes of salt.
const EspAeadKeyBytes = 20

// EspAeadKeyHexLength is the same length in hexadecimal characters.
const EspAeadKeyHexLength = EspAeadKeyBytes * 2 // 40

// EspICVLen is the integrity check value length in bits.
const EspICVLen = 128

// EspReplayWindow is the anti-replay window size of a new security
// association, in packets.
const EspReplayWindow = 32

// EspIdentity is everything the SPI derivation needs: the outer endpoints
// and the inner address pair, each as the two ends see them.
type EspIdentity struct {
	Local, Remote           string
	InnerLocal, InnerRemote string
}

// ParseEspKey decodes a 40-character hexadecimal ESP key into its 20 bytes.
func ParseEspKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != EspAeadKeyHexLength {
		return nil, fmt.Errorf("ESP key must be %d hexadecimal characters, got %d", EspAeadKeyHexLength, len(s))
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ESP key is not hexadecimal: %w", err)
	}
	return key, nil
}

// GenerateEspKey returns a fresh random ESP key as 40 hexadecimal characters.
func GenerateEspKey() (string, error) {
	key := make([]byte, EspAeadKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating an ESP key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// EspSPIs derives the outbound and inbound SPIs for the local side of an ESP
// tunnel. The two values are distinct and non-zero, and the pair is the same
// whichever end computes it.
func EspSPIs(id EspIdentity) (spiOut, spiIn uint32, err error) {
	local, err := netip.ParseAddr(strings.TrimSpace(id.Local))
	if err != nil {
		return 0, 0, fmt.Errorf("local endpoint %q is not an IP address: %w", id.Local, err)
	}
	remote, err := netip.ParseAddr(strings.TrimSpace(id.Remote))
	if err != nil {
		return 0, 0, fmt.Errorf("remote endpoint %q is not an IP address: %w", id.Remote, err)
	}
	lo, hi := local, remote
	localIsFirst := true
	if local.Compare(remote) > 0 {
		lo, hi = remote, local
		localIsFirst = false
	}
	// The inner pair is ordered the same way, so a tunnel whose endpoints
	// are listed in the opposite order still derives the same SPIs.
	innerLo, innerHi := canonicalInner(id.InnerLocal, id.InnerRemote)
	spiFirst := deriveSPI("esp-spi|a|", lo, hi, innerLo, innerHi)
	spiSecond := deriveSPI("esp-spi|b|", lo, hi, innerLo, innerHi)
	if localIsFirst {
		return spiFirst, spiSecond, nil
	}
	return spiSecond, spiFirst, nil
}

// canonicalInner orders an inner address pair the same way EspSPIs orders
// the outer endpoints, so the two ends agree on it. An empty side stays
// empty; a pair with only one side keeps that side.
func canonicalInner(a, b string) (string, string) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return a, b
	}
	pa, errA := netip.ParseAddr(a)
	pb, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil || pa.Compare(pb) <= 0 {
		return a, b
	}
	return b, a
}

func deriveSPI(label string, lo, hi netip.Addr, innerLo, innerHi string) uint32 {
	h := sha256.New()
	fmt.Fprintf(h, "%s%s|%s|%s|%s", label, lo.String(), hi.String(), innerLo, innerHi)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[:4])
	if v == 0 {
		v = 1
	}
	return v
}

// EspIfID derives the xfrm interface identifier for one side of an ESP
// tunnel. It only has to be unique among this host's xfrm interfaces, so
// the local interface name is part of the input and the two ends need not
// agree on it.
func EspIfID(local, remote, name string) uint32 {
	h := sha256.New()
	fmt.Fprintf(h, "esp-ifid|%s|%s|%s", strings.TrimSpace(local), strings.TrimSpace(remote), strings.TrimSpace(name))
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[:4])
	if v == 0 {
		v = 1
	}
	return v
}

// espSA returns the source, destination and SPI of one direction's security
// association, from the perspective of the host creating it. The outbound
// association carries traffic to the remote endpoint; the inbound one receives
// traffic from it.
func espSA(spec TunnelSpec, outbound bool) (src, dst string, spi uint32) {
	if outbound {
		return spec.Local, spec.Remote, spec.EspSPIOut
	}
	return spec.Remote, spec.Local, spec.EspSPIIn
}

// checkEspSpec verifies that a specification carries everything the link
// layer needs to build an ESP tunnel. The service and validation layers
// normally guarantee this; a stored or adopted record that lost its key
// still reaches this check, so it must fail here rather than build a
// half-formed tunnel.
func checkEspSpec(ctx context.Context, spec TunnelSpec) error {
	switch {
	case len(spec.EspKey) != EspAeadKeyBytes:
		return i18n.Errorf(ctx, "an ESP tunnel needs a %d-byte key", EspAeadKeyBytes)
	case spec.EspSPIOut == 0 || spec.EspSPIIn == 0:
		return i18n.Errorf(ctx, "an ESP tunnel needs both security association identifiers")
	case spec.EspIfID == 0:
		return i18n.Errorf(ctx, "an ESP tunnel needs an interface identifier")
	case spec.FwMark != nil:
		return i18n.Errorf(ctx, "an ESP tunnel does not carry a firewall mark")
	case spec.IsIgnoreDf:
		return i18n.Errorf(ctx, "an ESP tunnel does not carry an ignore-df flag")
	case spec.IsPathMtuDiscovery:
		return i18n.Errorf(ctx, "an ESP tunnel does not carry a path-MTU-discovery flag")
	}
	return nil
}
