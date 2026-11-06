package link

import (
	"strings"
	"testing"
)

func TestOmniArgsFollowEachTransportsRealFlags(t *testing.T) {
	addresses := []Address{{Address: "10.10.1.1", PrefixLength: 30, Peer: "10.10.1.2"}}
	base := TunnelSpec{
		Name: "omni-a-1", Local: "203.0.113.10", Remote: "198.51.100.20",
		OmniKey: strings.Repeat("a", 64), OmniPort: 8443, OmniConns: 8, OmniMode: OmniModeListen, Mtu: 1400,
	}
	cases := []struct {
		transport string
		want      []string
		notWant   []string
	}{
		// udp is symmetric: no -s, no -N.
		{OmniTransportUDP, []string{"omnitun", "udp", "-L", "203.0.113.10", "-R", "198.51.100.20", "-A", "10.10.1.1", "-P", "10.10.1.2", "-p", "8443", "-k", strings.Repeat("a", 64), "-T", "omni-a-1", "-M", "1400"}, []string{"-s", "-N"}},
		// tcp takes -s but no -N.
		{OmniTransportTCP, []string{"omnitun", "tcp", "-s"}, []string{"-N"}},
		// mux and ws take -s and -N.
		{OmniTransportMUX, []string{"omnitun", "mux", "-s", "-N", "8"}, nil},
		{OmniTransportWS, []string{"omnitun", "ws", "-s", "-N", "8"}, nil},
		// icmp takes neither a port nor a key.
		{OmniTransportICMP, []string{"omnitun", "icmp", "-s"}, []string{"-p", "-k", "-N"}},
	}
	for _, c := range cases {
		spec := base
		spec.OmniTransport = c.transport
		got := OmniArgs("/usr/local/bin/omnitun", spec, addresses)
		joined := strings.Join(got, " ")
		for _, w := range c.want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: args %q do not contain %q", c.transport, joined, w)
			}
		}
		for _, nw := range c.notWant {
			if strings.Contains(joined, " "+nw+" ") || strings.HasSuffix(joined, " "+nw) {
				t.Errorf("%s: args %q contain %q, which this transport does not take", c.transport, joined, nw)
			}
		}
	}
}

func TestOmniKeyRoundTrip(t *testing.T) {
	key, err := GenerateOmniKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 64 {
		t.Fatalf("the key is %d characters, want 64", len(key))
	}
	if err := ParseOmniKey(key); err != nil {
		t.Fatalf("a generated key did not parse: %v", err)
	}
	if err := ParseOmniKey("short"); err == nil {
		t.Fatal("a short key parsed")
	}
}

func TestOmniBinaryURLIsPinnedToARelease(t *testing.T) {
	url := OmniBinaryURL("amd64")
	if !strings.Contains(url, OmniBinaryVersion) || !strings.Contains(url, "omnitun-amd64") {
		t.Fatalf("the binary url is not pinned to the release: %q", url)
	}
	if _, ok := OmniBinaryChecksums["amd64"]; !ok {
		t.Fatal("no pinned checksum for amd64")
	}
}
