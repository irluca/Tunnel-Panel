package cluster

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeSettings struct {
	values map[string]any
}

func (f fakeSettings) Get(key string) (any, bool) {
	v, ok := f.values[key]
	return v, ok
}

func TestCheckReportsAReachablePeer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system/health" {
			t.Errorf("the peer was asked at %q, want the health endpoint", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(healthResponse{Status: "ok", Version: "1.2.3", UptimeSeconds: 3600})
	}))
	defer server.Close()

	c := New(fakeSettings{values: map[string]any{
		"cluster.peers": []any{map[string]any{"name": "foreign-1", "url": server.URL}},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	statuses := c.Check(context.Background())
	if len(statuses) != 1 {
		t.Fatalf("peers = %d, want 1", len(statuses))
	}
	s := statuses[0]
	if !s.Reachable || s.Status != "ok" || s.Version != "1.2.3" || s.UptimeSeconds != 3600 {
		t.Fatalf("peer status = %+v", s)
	}
}

func TestCheckReportsAnUnreachablePeerWithTheReason(t *testing.T) {
	c := New(fakeSettings{values: map[string]any{
		"cluster.peers": []any{map[string]any{"name": "dead", "url": "http://127.0.0.1:1"}},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	statuses := c.Check(context.Background())
	if len(statuses) != 1 {
		t.Fatalf("peers = %d, want 1", len(statuses))
	}
	s := statuses[0]
	if s.Reachable || s.Error == "" {
		t.Fatalf("an unreachable peer was reported as fine: %+v", s)
	}
}

func TestHealthURLKeepsAWebPath(t *testing.T) {
	got, err := healthURL("https://10.0.0.1:24592/abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://10.0.0.1:24592/abc123/api/v1/system/health" {
		t.Fatalf("health url = %q", got)
	}
}
