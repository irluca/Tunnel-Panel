package tunnel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/link"
)

// An IPv6 tunnel has no TTL field: the outer header carries a hop limit, and it
// is the same octet. The writer knows this — link.TunnelArgs uses the hop limit
// when one is set and falls back to the TTL — and the reader knows it too,
// mapping the kernel's hoplimit back onto Ttl. Verification did not: it compared
// the kernel's hop limit against the *desired TTL*, which is a different number
// whenever an operator sets a hop limit without also setting the TTL to match.
//
// Seen on a live host, creating an IP6GRE tunnel with hop_limit 64 and no TTL:
//
//	409 APPLY_FAILED  gre6-c: verification failed: the interface exists but
//	                  TTL is 64, not 255
//
// The apply rolled back correctly, so nothing was left behind — but the tunnel
// could not be created at all. Setting both fields to the same number worked,
// which is what pins the cause: the two write one octet and only one of them
// was being checked. The hop-limit control is new, so this became reachable the
// moment an operator could set it.
func TestAnIPv6TunnelIsVerifiedAgainstItsHopLimit(t *testing.T) {
	hop := 64
	desired := link.TunnelSpec{
		Name: "gre6-1", Kind: link.KindIP6GRE,
		Local: "2001:db8::1", Remote: "2001:db8::2",
		// The TTL the panel defaults to, which is not what was asked for.
		Ttl: 255, Mtu: 1400,
		HopLimit: &hop,
	}
	// What the kernel reports: the hop limit, mapped onto Ttl by the reader.
	observed := link.Link{
		Name: "gre6-1", MTU: 1400,
		Tunnel: &link.TunnelAttrs{Local: "2001:db8::1", Remote: "2001:db8::2", Ttl: 64},
	}

	// The parameter comparisons are reported as one aggregated check, so the
	// assertion is on its detail rather than on a per-field name. Asserting on
	// a check called "TTL" passed vacuously, because no such check exists — the
	// IPv4 case below is what caught that.
	for _, check := range parameterChecks(context.Background(), desired, observed) {
		if !check.Ok && (strings.Contains(check.Detail, "TTL") || strings.Contains(check.Detail, "hop limit")) {
			t.Errorf("verification failed for an IPv6 tunnel whose hop limit was honoured: %s\n"+
				"The hop limit is what was written, so it is what has to be checked.", check.Detail)
		}
	}
}

// A userspace relay (OmniTunnel, GRE-over-WSS) creates its TUN device
// asynchronously after the unit starts, a second or two later, while a
// kernel interface exists the moment the link command returns. Verify used
// to look the interface up exactly once, so every relay apply rolled back
// before the daemon had a chance to come up:
//
//	409 APPLY_FAILED  omnitunnel-a-2: verification failed: the interface
//	                  omnitunnel-a-2 does not exist
//
// Seen live on 20 Nov 2026: omnitun printed "obsctun up" and the interface
// appeared when the same binary was run by hand, but the panel had already
// rolled back. The wait polls for the link instead of failing on the first
// lookup.
func TestVerifyWaitsForARelayInterfaceToAppear(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	go func() {
		time.Sleep(400 * time.Millisecond)
		h.links.AddLink(link.Link{Name: "omnitunnel-a-1"})
	}()
	observed, err := h.service.waitForLink(ctx, "omnitunnel-a-1")
	if err != nil {
		t.Fatalf("waitForLink gave up on a link that appeared after 400ms: %v", err)
	}
	if observed.Name != "omnitunnel-a-1" {
		t.Errorf("waitForLink returned the wrong link: %q", observed.Name)
	}
}

// The ordinary case has to keep working: an IPv4 tunnel has a TTL and no hop
// limit, and a genuine mismatch must still be reported.
func TestAnIPv4TunnelIsStillVerifiedAgainstItsTtl(t *testing.T) {
	desired := link.TunnelSpec{
		Name: "gre-1", Kind: link.KindGRE,
		Local: "203.0.113.1", Remote: "198.51.100.1", Ttl: 255, Mtu: 1472,
	}
	observed := link.Link{
		Name: "gre-1", MTU: 1472,
		Tunnel: &link.TunnelAttrs{Local: "203.0.113.1", Remote: "198.51.100.1", Ttl: 64},
	}

	var sawMismatch bool
	for _, check := range parameterChecks(context.Background(), desired, observed) {
		if !check.Ok && strings.Contains(check.Detail, "TTL") {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Error("an IPv4 tunnel running with the wrong TTL was reported as verified")
	}
}
