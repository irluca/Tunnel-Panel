package grewss

import (
	"bytes"
	"testing"
)

func ipv4Packet() []byte {
	// A minimal IPv4 header (version 4, IHL 5) with a 4-byte payload.
	pkt := []byte{0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		10, 0, 0, 1, 10, 0, 0, 2, 'd', 'a', 't', 'a'}
	return pkt
}

func ipv6Packet() []byte {
	// A minimal IPv6 header (version 6) with a 4-byte payload.
	pkt := []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x11, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		'd', 'a', 't', 'a'}
	return pkt
}

func TestGreRoundTrip(t *testing.T) {
	for _, pkt := range [][]byte{ipv4Packet(), ipv6Packet()} {
		gre, err := Encapsulate(pkt, 12345)
		if err != nil {
			t.Fatalf("encapsulate: %v", err)
		}
		if len(gre) != len(pkt)+greHeaderLenKey {
			t.Fatalf("GRE packet is %d bytes, want %d", len(gre), len(pkt)+greHeaderLenKey)
		}
		back, err := Decapsulate(gre, 12345)
		if err != nil {
			t.Fatalf("decapsulate: %v", err)
		}
		if !bytes.Equal(back, pkt) {
			t.Fatal("the packet did not survive the round trip")
		}
	}
}

func TestGreWrongKeyIsRejected(t *testing.T) {
	gre, err := Encapsulate(ipv4Packet(), 12345)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decapsulate(gre, 999); err == nil {
		t.Fatal("a packet with the wrong key was accepted")
	}
}

func TestGreBadPacketsAreRejected(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		{0x00},
		{0x00, 0x00, 0x08, 0x00}, // no key bit, no key
		{0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x30, 0x39}, // key present but no packet
	} {
		if _, err := Decapsulate(bad, 12345); err == nil {
			t.Fatalf("packet %v was accepted", bad)
		}
	}
	// A header that says IPv4 but carries IPv6.
	gre, err := Encapsulate(ipv6Packet(), 12345)
	if err != nil {
		t.Fatal(err)
	}
	gre[2], gre[3] = 0x08, 0x00
	if _, err := Decapsulate(gre, 12345); err == nil {
		t.Fatal("a packet whose header disagrees with its contents was accepted")
	}
}

func TestGreNonIPPacketIsRejected(t *testing.T) {
	if _, err := Encapsulate([]byte{0x70, 0x00, 0x00, 0x00}, 1); err == nil {
		t.Fatal("a packet that is neither IPv4 nor IPv6 was encapsulated")
	}
}
