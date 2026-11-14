package pairing

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
)

func i64(v int64) *int64 { return &v }

func samplePayload() Payload {
	return Payload{
		TunnelTypeID:    model.TunnelTypeGRE,
		TunnelSideID:    model.TunnelSideA,
		Name:            "gre-a-7",
		IsNameTemplated: true,
		TunnelNumber:    i64(7),
		LocalEndpoint:   "203.0.113.10",
		RemoteEndpoint:  "198.51.100.20",
		Ttl:             255,
		Tos:             "inherit",
		Mtu:             1472,
		IKey:            i64(2749365187),
		OKey:            i64(2749365187),
		AddressPoolID:   i64(10),
		Addresses: []PairAddress{
			{AddressA: "172.17.7.1", AddressB: "172.17.7.2", PrefixLength: 30, IsPrimary: true},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	code, err := Encode(samplePayload())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if !strings.HasPrefix(code, Prefix) {
		t.Fatalf("code %q does not carry the version prefix", code)
	}
	// The point of the format is that an operator can copy it in one piece.
	if strings.ContainsAny(code, " \n\t+/=") {
		t.Fatalf("the code contains characters that do not survive a copy: %q", code)
	}

	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	want := samplePayload()
	want.Version = Version
	if decoded.LocalEndpoint != want.LocalEndpoint || decoded.RemoteEndpoint != want.RemoteEndpoint {
		t.Fatalf("endpoints did not survive the round trip: %+v", decoded)
	}
	if decoded.Mtu != 1472 || decoded.Ttl != 255 {
		t.Fatalf("numeric fields did not survive: %+v", decoded)
	}
	if decoded.IKey == nil || *decoded.IKey != 2749365187 {
		t.Fatalf("the key did not survive: %v", decoded.IKey)
	}
	if len(decoded.Addresses) != 1 || decoded.Addresses[0].AddressB != "172.17.7.2" {
		t.Fatalf("addresses did not survive: %+v", decoded.Addresses)
	}
}

// The ESP key is the one secret that must be identical on both ends, so it
// travels in the code like the GRE keys do — and the summary says only that
// it is there, never what it is.
func TestEspKeySurvivesTheRoundTrip(t *testing.T) {
	key := "00112233445566778899aabbccddeeff00112233"
	p := samplePayload()
	p.TunnelTypeID = model.TunnelTypeESP
	p.IKey = nil
	p.OKey = nil
	p.EspKey = &key

	code, err := Encode(p)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if decoded.EspKey == nil || *decoded.EspKey != key {
		t.Fatalf("the ESP key did not survive: %v", decoded.EspKey)
	}
	in := decoded.Flipped()
	if in.EspKey == nil || *in.EspKey != key {
		t.Fatalf("the flipped tunnel lost the ESP key: %v", in.EspKey)
	}
	if in.IKey != nil || in.OKey != nil {
		t.Fatalf("an ESP tunnel flipped with GRE keys: %+v", in)
	}
	summary := decoded.Summarise()
	if !summary.EspKeyPresent {
		t.Fatal("the summary does not say the shared secret is there")
	}
}
func TestFlipMirrorsTheSide(t *testing.T) {
	code, err := Encode(samplePayload())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	in := decoded.Flipped()

	if in.TunnelSideID != model.TunnelSideB {
		t.Fatalf("side = %d, want B", in.TunnelSideID)
	}
	if in.LocalEndpoint != "198.51.100.20" || in.RemoteEndpoint != "203.0.113.10" {
		t.Fatalf("endpoints were not mirrored: local %s, remote %s", in.LocalEndpoint, in.RemoteEndpoint)
	}
	if len(in.Addresses) != 1 {
		t.Fatalf("addresses = %+v", in.Addresses)
	}
	if in.Addresses[0].Address != "172.17.7.2" || in.Addresses[0].PeerAddress != "172.17.7.1" {
		t.Fatalf("the address was not mirrored: %+v", in.Addresses[0])
	}

	// Everything else must be identical, or the tunnel comes up and passes
	// nothing.
	if in.TunnelTypeID != model.TunnelTypeGRE || in.Mtu != 1472 || in.Ttl != 255 {
		t.Fatalf("shared parameters changed: %+v", in)
	}
	if in.IKey == nil || *in.IKey != 2749365187 || in.OKey == nil || *in.OKey != 2749365187 {
		t.Fatalf("keys changed: %v, %v", in.IKey, in.OKey)
	}
	// A templated name belongs to the server that generated it.
	if in.InterfaceName != "" {
		t.Fatalf("a templated name must not be copied to the other server, got %q", in.InterfaceName)
	}
}

func TestFlipBackReturnsTheOriginalSide(t *testing.T) {
	first := samplePayload().Flipped()
	if first.TunnelSideID != model.TunnelSideB {
		t.Fatalf("first flip = %d", first.TunnelSideID)
	}

	// Encoding the far side and flipping again returns to where it started.
	back := Payload{
		TunnelTypeID:   first.TunnelTypeID,
		TunnelSideID:   first.TunnelSideID,
		LocalEndpoint:  first.LocalEndpoint,
		RemoteEndpoint: first.RemoteEndpoint,
		Mtu:            first.Mtu,
		Ttl:            first.Ttl,
		Addresses: []PairAddress{
			{AddressA: "172.17.7.1", AddressB: "172.17.7.2", PrefixLength: 30},
		},
	}.Flipped()

	if back.TunnelSideID != model.TunnelSideA {
		t.Fatalf("second flip = %d, want A", back.TunnelSideID)
	}
	if back.LocalEndpoint != "203.0.113.10" || back.RemoteEndpoint != "198.51.100.20" {
		t.Fatalf("the second flip did not return to the original endpoints: %+v", back)
	}
	if back.Addresses[0].Address != "172.17.7.1" {
		t.Fatalf("the second flip did not return to the original address: %+v", back.Addresses[0])
	}
}

func TestHandChosenNameIsNotCopied(t *testing.T) {
	p := samplePayload()
	p.IsNameTemplated = false
	p.Name = "office-link"
	if got := p.Flipped().InterfaceName; got != "office-link" {
		t.Fatalf("a hand-chosen name should be offered as a starting point, got %q", got)
	}
}

func TestCorruptCodeIsRejected(t *testing.T) {
	code, err := Encode(samplePayload())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}

	// Flipping one character of the body breaks the checksum.
	body := []byte(code)
	index := len(body) - 3
	if body[index] == 'A' {
		body[index] = 'B'
	} else {
		body[index] = 'A'
	}
	if _, err := Decode(string(body)); err == nil {
		t.Fatal("an altered pairing code was accepted")
	}

	cases := map[string]string{
		"":                         "empty",
		"nonsense":                 "no version prefix",
		"v1.":                      "no body",
		"v1.!!!!":                  "not base64",
		"v2." + code[len(Prefix):]: "unknown version",
		"v1.AAAA":                  "too short to hold a payload",
		code[:len(code)-8]:         "truncated",
	}
	for candidate, why := range cases {
		if _, err := Decode(candidate); err == nil {
			t.Fatalf("%q (%s) was accepted", candidate, why)
		}
	}
}

func TestUnknownVersionSaysSo(t *testing.T) {
	code, _ := Encode(samplePayload())
	_, err := Decode("v9." + code[len(Prefix):])
	if err == nil {
		t.Fatal("a future version was accepted")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("the error should name the version problem, got %q", err)
	}
}

func TestUnknownTunnelTypeIsRejected(t *testing.T) {
	p := samplePayload()
	p.TunnelTypeID = 999
	code, err := Encode(p)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if _, err := Decode(code); err == nil {
		t.Fatal("a code naming an unknown tunnel type was accepted")
	}

	p = samplePayload()
	p.TunnelSideID = 99
	code, _ = Encode(p)
	if _, err := Decode(code); err == nil {
		t.Fatal("a code naming an unknown side was accepted")
	}
}

func TestSummaryDescribesTheFarEnd(t *testing.T) {
	summary := samplePayload().Summarise()
	if summary.FromSide != "A" || summary.ToSide != "B" {
		t.Fatalf("sides = %s -> %s", summary.FromSide, summary.ToSide)
	}
	if summary.LocalEndpoint != "198.51.100.20" || summary.RemoteEndpoint != "203.0.113.10" {
		t.Fatalf("the summary must describe the far end: %+v", summary)
	}
	// Keys are always shown as integers, never in the dotted form iproute2 uses.
	if summary.IKey != "2749365187" {
		t.Fatalf("ikey = %q, want the integer form", summary.IKey)
	}
}

func TestCodeStaysShortEnoughToCopy(t *testing.T) {
	code, err := Encode(samplePayload())
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if len(code) > 400 {
		t.Fatalf("the pairing code is %d characters, which is too long to copy comfortably", len(code))
	}
}

func TestEzKeyPortAndListsSurviveTheRoundTrip(t *testing.T) {
	key, err := link.GenerateEzKey()
	if err != nil {
		t.Fatalf("generating an EZTunnel key failed: %v", err)
	}
	port := int64(8443)
	transport := "mirage"
	httpPath := "/tunnel"
	rawProfile := "tcp"
	rawInterface := "eth0"
	uplink := "tcp"
	downlink := "udp"
	sources := []string{"203.0.113.7", "198.51.100.23"}
	expected := []string{"203.0.113.7"}
	p := samplePayload()
	p.TunnelTypeID = model.TunnelTypeEZTunnel
	p.EzTransport = &transport
	p.EzKey = &key
	p.EzPort = &port
	p.EzHttpPath = &httpPath
	p.EzRawProfile = &rawProfile
	p.EzRawInterface = &rawInterface
	p.EzMirageUplink = &uplink
	p.EzMirageDownlink = &downlink
	p.EzSpoofSources = &sources
	p.EzMirageExpected = &expected

	code, err := Encode(p)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if decoded.EzTransport == nil || *decoded.EzTransport != transport {
		t.Fatalf("the EZTunnel transport did not survive: %v", decoded.EzTransport)
	}
	if decoded.EzKey == nil || *decoded.EzKey != key {
		t.Fatalf("the EZTunnel key did not survive: %v", decoded.EzKey)
	}
	if decoded.EzPort == nil || *decoded.EzPort != port {
		t.Fatalf("the EZTunnel port did not survive: %v", decoded.EzPort)
	}
	if decoded.EzSpoofSources == nil || len(*decoded.EzSpoofSources) != 2 || (*decoded.EzSpoofSources)[0] != "203.0.113.7" {
		t.Fatalf("the spoof sources did not survive: %v", decoded.EzSpoofSources)
	}
	if decoded.EzMirageExpected == nil || len(*decoded.EzMirageExpected) != 1 {
		t.Fatalf("the expected sources did not survive: %v", decoded.EzMirageExpected)
	}
	in := decoded.Flipped()
	if in.EzKey == nil || *in.EzKey != key {
		t.Fatalf("the flipped tunnel lost the EZTunnel key: %v", in.EzKey)
	}
	if in.EzSpoofSources == nil || len(*in.EzSpoofSources) != 2 {
		t.Fatalf("the flipped tunnel lost the spoof sources: %v", in.EzSpoofSources)
	}
	// The summary never shows the key itself, only that one travelled.
	summary := decoded.Summarise()
	if summary.EzTransport != transport || !summary.EzKeyPresent || summary.EzPort == nil || *summary.EzPort != port {
		t.Fatalf("the summary does not describe the EZTunnel tunnel: %+v", summary)
	}
}

func TestOmniKeyAndPortSurviveTheRoundTrip(t *testing.T) {
	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	port := int64(8443)
	conns := int64(8)
	transport := "mux"
	p := samplePayload()
	p.TunnelTypeID = model.TunnelTypeOmniTunnel
	p.OmniTransport = &transport
	p.OmniKey = &key
	p.OmniPort = &port
	p.OmniConns = &conns

	code, err := Encode(p)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if decoded.OmniTransport == nil || *decoded.OmniTransport != transport {
		t.Fatalf("the OmniTunnel transport did not survive: %v", decoded.OmniTransport)
	}
	if decoded.OmniKey == nil || *decoded.OmniKey != key {
		t.Fatalf("the OmniTunnel key did not survive: %v", decoded.OmniKey)
	}
	if decoded.OmniPort == nil || *decoded.OmniPort != port {
		t.Fatalf("the OmniTunnel port did not survive: %v", decoded.OmniPort)
	}
	if decoded.OmniConns == nil || *decoded.OmniConns != conns {
		t.Fatalf("the parallel-link count did not survive: %v", decoded.OmniConns)
	}
	in := decoded.Flipped()
	if in.OmniKey == nil || *in.OmniKey != key {
		t.Fatalf("the flipped tunnel lost the OmniTunnel key: %v", in.OmniKey)
	}
	if in.OmniPort == nil || *in.OmniPort != port {
		t.Fatalf("the flipped tunnel lost the OmniTunnel port: %v", in.OmniPort)
	}
}

func TestWssTokenAndPortSurviveTheRoundTrip(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	port := int64(8443)
	p := samplePayload()
	p.TunnelTypeID = model.TunnelTypeGREWSS
	p.WssToken = &token
	p.WssPort = &port

	code, err := Encode(p)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	decoded, err := Decode(code)
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if decoded.WssToken == nil || *decoded.WssToken != token {
		t.Fatalf("the WSS token did not survive: %v", decoded.WssToken)
	}
	if decoded.WssPort == nil || *decoded.WssPort != port {
		t.Fatalf("the WSS port did not survive: %v", decoded.WssPort)
	}
	in := decoded.Flipped()
	if in.WssToken == nil || *in.WssToken != token {
		t.Fatalf("the flipped tunnel lost the WSS token: %v", in.WssToken)
	}
	if in.WssPort == nil || *in.WssPort != port {
		t.Fatalf("the flipped tunnel lost the WSS port: %v", in.WssPort)
	}
	summary := decoded.Summarise()
	if !summary.WssTokenPresent {
		t.Fatal("the summary does not say the shared secret is there")
	}
	if summary.WssPort == nil || *summary.WssPort != port {
		t.Fatalf("the summary lost the WSS port: %v", summary.WssPort)
	}
}
