// Package grewss carries GRE packets over a WebSocket Secure stream, for
// paths that filter IP protocol 47.
//
// A GRE tunnel is normally a kernel interface whose packets leave as IP
// protocol 47. Some paths drop those packets entirely, so neither GRE nor
// ESP can ever come up on them. This relay moves the same packets — the same
// GRE header, the same key — over a TLS WebSocket instead, which the path
// sees as ordinary HTTPS. Both ends run the relay: one listens, one dials,
// and each end feeds the packets to a TUN interface the panel manages like
// any other tunnel interface.
//
// The GRE header is the real one (RFC 2784), with the key bit set and the
// panel's GRE key in it, so a packet the relay emits is a genuine GRE packet
// and the peer verifies the key before accepting it. The protocol type is
// the IP version of the packet inside (0x0800 for IPv4, 0x86DD for IPv6).
package grewss

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// GRE header constants (RFC 2784).
const (
	greHeaderLen    = 4
	greHeaderLenKey = 8
	greKeyPresent   = 0x2000
	ethertypeIPv4   = 0x0800
	ethertypeIPv6   = 0x86DD
	maxPacketSize   = 65535
)

// ErrBadPacket is returned when a packet is not a GRE packet the relay can use.
var ErrBadPacket = errors.New("not a GRE packet")

// Encapsulate wraps an IP packet in a GRE header carrying the key. The
// returned slice is a new allocation; the input is not modified.
func Encapsulate(ip []byte, key uint32) ([]byte, error) {
	if len(ip) == 0 {
		return nil, fmt.Errorf("%w: empty packet", ErrBadPacket)
	}
	proto, err := ipProtocol(ip)
	if err != nil {
		return nil, err
	}
	out := make([]byte, greHeaderLenKey+len(ip))
	binary.BigEndian.PutUint16(out[0:2], greKeyPresent)
	binary.BigEndian.PutUint16(out[2:4], proto)
	binary.BigEndian.PutUint32(out[4:8], key)
	copy(out[greHeaderLenKey:], ip)
	return out, nil
}

// Decapsulate strips the GRE header and returns the IP packet inside, after
// verifying the key. The returned slice aliases the input.
func Decapsulate(gre []byte, key uint32) ([]byte, error) {
	if len(gre) < greHeaderLen {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a GRE header", ErrBadPacket, len(gre))
	}
	flags := binary.BigEndian.Uint16(gre[0:2])
	if flags != greKeyPresent {
		return nil, fmt.Errorf("%w: flags 0x%04x are not the keyed GRE header this relay writes", ErrBadPacket, flags)
	}
	if len(gre) < greHeaderLenKey {
		return nil, fmt.Errorf("%w: the header promises a key the packet does not carry", ErrBadPacket)
	}
	if got := binary.BigEndian.Uint32(gre[4:8]); got != key {
		return nil, fmt.Errorf("%w: the key does not match", ErrBadPacket)
	}
	proto := binary.BigEndian.Uint16(gre[2:4])
	ip := gre[greHeaderLenKey:]
	if len(ip) == 0 {
		return nil, fmt.Errorf("%w: no packet inside the GRE header", ErrBadPacket)
	}
	if want, err := ipProtocol(ip); err != nil {
		return nil, err
	} else if want != proto {
		return nil, fmt.Errorf("%w: the header says %s but the packet inside is %s", ErrBadPacket, etherName(proto), etherName(want))
	}
	return ip, nil
}

// ipProtocol returns the GRE protocol type for the IP packet: IPv4 or IPv6,
// from the version nibble of the first byte.
func ipProtocol(ip []byte) (uint16, error) {
	if len(ip) == 0 {
		return 0, fmt.Errorf("%w: empty packet", ErrBadPacket)
	}
	switch ip[0] >> 4 {
	case 4:
		return ethertypeIPv4, nil
	case 6:
		return ethertypeIPv6, nil
	}
	return 0, fmt.Errorf("%w: version %d is neither IPv4 nor IPv6", ErrBadPacket, ip[0]>>4)
}

func etherName(proto uint16) string {
	switch proto {
	case ethertypeIPv4:
		return "IPv4"
	case ethertypeIPv6:
		return "IPv6"
	}
	return fmt.Sprintf("0x%04x", proto)
}
