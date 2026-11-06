package dns

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

type failoverSettings struct {
	values map[string]any
}

func (f failoverSettings) Bool(key string) bool {
	v, _ := f.values[key].(bool)
	return v
}

func (f failoverSettings) String(key string) string {
	v, _ := f.values[key].(string)
	return v
}

func (f failoverSettings) Int(key string) int64 {
	v, _ := f.values[key].(int64)
	return v
}

func (f failoverSettings) Get(key string) (any, bool) {
	v, ok := f.values[key]
	return v, ok
}

type fakeTunnels struct {
	records map[int64]tunnel.Record
}

func (f *fakeTunnels) ByID(ctx context.Context, id int64) (tunnel.Record, error) {
	rec, ok := f.records[id]
	if !ok {
		return tunnel.Record{}, errNotFound
	}
	return rec, nil
}

var errNotFound = errString("no such tunnel")

type errString string

func (e errString) Error() string { return string(e) }

type fakeSnapshots struct {
	snaps []monitor.Snapshot
}

func (f *fakeSnapshots) Summary() []monitor.Snapshot { return f.snaps }

// The name moves to the first healthy candidate, and stays there while it
// is healthy: a check that finds everything healthy makes no change.
func TestFailoverMovesToTheFirstHealthyCandidate(t *testing.T) {
	var puts int
	var lastContent string
	current := "1.1.1.1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(apiResponse[[]Record]{Success: true, Result: []Record{
				{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: current, TTL: 60},
			}})
		case r.Method == http.MethodPut:
			puts++
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			lastContent, _ = payload["content"].(string)
			current = lastContent
			_ = json.NewEncoder(w).Encode(apiResponse[Record]{Success: true, Result: Record{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: lastContent, TTL: 60}})
		}
	}))
	defer server.Close()

	settings := failoverSettings{values: map[string]any{
		"dns.cloudflare.enabled":                   true,
		"dns.cloudflare.api_token":                 "tok",
		"dns.cloudflare.zone_id":                   "zone1",
		"dns.cloudflare.record_name":               "vpn.example.com",
		"dns.cloudflare.record_type":               "A",
		"dns.cloudflare.ttl":                       int64(60),
		"dns.cloudflare.failover_tunnels":          []any{float64(1), float64(2)},
		"dns.cloudflare.rotation_interval_seconds": int64(0),
	}}
	tunnels := &fakeTunnels{records: map[int64]tunnel.Record{
		1: {Tunnel: model.Tunnel{TunnelID: 1, RemoteEndpoint: "1.1.1.1"}},
		2: {Tunnel: model.Tunnel{TunnelID: 2, RemoteEndpoint: "2.2.2.2"}},
	}}
	// Tunnel 1 is Down, tunnel 2 is Up: the name must move to 2.2.2.2.
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{
		{TunnelID: 1, MonitorStateID: model.MonitorStateDown},
		{TunnelID: 2, MonitorStateID: model.MonitorStateUp},
	}}
	f := NewFailover(settings, tunnels, snaps, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.Client = New("tok")
	f.Client.BaseURL = server.URL

	content, changed, err := f.Check(context.Background())
	if err != nil {
		t.Fatalf("the check failed: %v", err)
	}
	if !changed || content != "2.2.2.2" || lastContent != "2.2.2.2" {
		t.Fatalf("content = %q changed = %v last put = %q", content, changed, lastContent)
	}
	if puts != 1 {
		t.Fatalf("puts = %d, want 1", puts)
	}

	// A second check with the same health changes nothing.
	content, changed, err = f.Check(context.Background())
	if err != nil {
		t.Fatalf("the second check failed: %v", err)
	}
	if changed || puts != 1 {
		t.Fatalf("a healthy check changed the record: changed=%v puts=%d", changed, puts)
	}
}

// When nothing is healthy the record stays where it is.
func TestFailoverLeavesTheRecordAloneWhenNothingIsHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	settings := failoverSettings{values: map[string]any{
		"dns.cloudflare.enabled":                   true,
		"dns.cloudflare.api_token":                 "tok",
		"dns.cloudflare.zone_id":                   "zone1",
		"dns.cloudflare.record_name":               "vpn.example.com",
		"dns.cloudflare.record_type":               "A",
		"dns.cloudflare.ttl":                       int64(60),
		"dns.cloudflare.failover_tunnels":          []any{float64(1)},
		"dns.cloudflare.rotation_interval_seconds": int64(0),
	}}
	tunnels := &fakeTunnels{records: map[int64]tunnel.Record{
		1: {Tunnel: model.Tunnel{TunnelID: 1, RemoteEndpoint: "1.1.1.1"}},
	}}
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{
		{TunnelID: 1, MonitorStateID: model.MonitorStateDown},
	}}
	f := NewFailover(settings, tunnels, snaps, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.Client = New("tok")
	f.Client.BaseURL = server.URL

	_, changed, err := f.Check(context.Background())
	if err != nil {
		t.Fatalf("the check failed: %v", err)
	}
	if changed {
		t.Fatal("the record moved when nothing was healthy")
	}
}
