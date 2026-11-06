package link

import (
	"strings"
	"testing"
)

func TestEspSPIsSymmetric(t *testing.T) {
	a := EspIdentity{Local: "203.0.113.10", Remote: "198.51.100.20", InnerLocal: "10.12.11.1", InnerRemote: "10.12.11.2"}
	b := EspIdentity{Local: "198.51.100.20", Remote: "203.0.113.10", InnerLocal: "10.12.11.2", InnerRemote: "10.12.11.1"}

	outA, inA, err := EspSPIs(a)
	if err != nil {
		t.Fatalf("EspSPIs(A) returned an unexpected error: %v", err)
	}
	outB, inB, err := EspSPIs(b)
	if err != nil {
		t.Fatalf("EspSPIs(B) returned an unexpected error: %v", err)
	}
	// Each side's outbound SPI is the other side's inbound SPI, which is
	// what makes the two ends agree without exchanging them.
	if outA != inB || inA != outB {
		t.Fatalf("SPIs do not mirror: A=(out %d, in %d), B=(out %d, in %d)", outA, inA, outB, inB)
	}
	if outA == 0 || inA == 0 {
		t.Fatal("an SPI is zero, which the kernel rejects")
	}
	if outA == inA {
		t.Fatal("the two directions share one SPI, so the kernel cannot tell them apart")
	}
}

func TestEspSPIsDeterministicAndDistinctPerTunnel(t *testing.T) {
	id := EspIdentity{Local: "203.0.113.10", Remote: "198.51.100.20", InnerLocal: "10.12.11.1", InnerRemote: "10.12.11.2"}
	out1, in1, err := EspSPIs(id)
	if err != nil {
		t.Fatalf("EspSPIs returned an unexpected error: %v", err)
	}
	out2, in2, err := EspSPIs(id)
	if err != nil {
		t.Fatalf("EspSPIs returned an unexpected error: %v", err)
	}
	if out1 != out2 || in1 != in2 {
		t.Fatal("EspSPIs is not deterministic: the same tunnel derives different SPIs")
	}
	// A second tunnel between the same two hosts, on a different inner
	// subnet, must get different SPIs or its security associations would
	// collide with the first tunnel's.
	other := EspIdentity{Local: "203.0.113.10", Remote: "198.51.100.20", InnerLocal: "10.12.12.1", InnerRemote: "10.12.12.2"}
	out3, in3, err := EspSPIs(other)
	if err != nil {
		t.Fatalf("EspSPIs returned an unexpected error: %v", err)
	}
	if out3 == out1 || in3 == in1 || out3 == in1 || in3 == out1 {
		t.Fatal("two tunnels between the same hosts share an SPI")
	}
}

func TestEspSPIsRejectBadEndpoints(t *testing.T) {
	if _, _, err := EspSPIs(EspIdentity{Local: "not-an-ip", Remote: "198.51.100.20"}); err == nil {
		t.Error("EspSPIs accepted an unparseable local endpoint")
	}
	if _, _, err := EspSPIs(EspIdentity{Local: "203.0.113.10", Remote: ""}); err == nil {
		t.Error("EspSPIs accepted an empty remote endpoint")
	}
}

func TestEspIfIDDeterministicAndNonZero(t *testing.T) {
	a := EspIfID("203.0.113.10", "198.51.100.20", "esp-iran-0")
	b := EspIfID("203.0.113.10", "198.51.100.20", "esp-iran-0")
	if a == 0 || a != b {
		t.Fatalf("EspIfID = %d, want a stable non-zero value", a)
	}
	if EspIfID("203.0.113.10", "198.51.100.20", "esp-iran-1") == a {
		t.Fatal("two interfaces with different names share an if_id")
	}
}

func TestParseAndGenerateEspKey(t *testing.T) {
	key, err := GenerateEspKey()
	if err != nil {
		t.Fatalf("GenerateEspKey returned an unexpected error: %v", err)
	}
	if len(key) != EspAeadKeyHexLength {
		t.Fatalf("generated key is %d characters, want %d", len(key), EspAeadKeyHexLength)
	}
	decoded, err := ParseEspKey(key)
	if err != nil {
		t.Fatalf("ParseEspKey rejected a generated key: %v", err)
	}
	if len(decoded) != EspAeadKeyBytes {
		t.Fatalf("decoded key is %d bytes, want %d", len(decoded), EspAeadKeyBytes)
	}
	if _, err := ParseEspKey(strings.Repeat("0", EspAeadKeyHexLength-2)); err == nil {
		t.Error("ParseEspKey accepted a short key")
	}
	if _, err := ParseEspKey(strings.Repeat("z", EspAeadKeyHexLength)); err == nil {
		t.Error("ParseEspKey accepted non-hexadecimal input")
	}
}
