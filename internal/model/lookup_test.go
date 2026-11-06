package model

import "testing"

func TestTunnelTypeESPRegistered(t *testing.T) {
	if TunnelTypeKind(TunnelTypeESP) != "esp" {
		t.Fatalf("TunnelTypeKind(ESP) = %q, want %q", TunnelTypeKind(TunnelTypeESP), "esp")
	}
	id, ok := TunnelTypeForKind("esp")
	if !ok || id != TunnelTypeESP {
		t.Fatalf("TunnelTypeForKind(%q) = (%d, %v), want (%d, true)", "esp", id, ok, TunnelTypeESP)
	}
	if !HasLookupValue("TunnelType", TunnelTypeESP) {
		t.Fatal("TunnelType lookup table has no ESP row")
	}
	// ESP carries its underlay over IPv4, so the endpoint family check
	// treats it like GRE rather than like the IPv6 types.
	if IsIPv6TunnelType(TunnelTypeESP) {
		t.Fatal("ESP is an IPv4-underlay type")
	}
}
