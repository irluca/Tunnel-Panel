package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A record already pointing at the content is left alone: a failover check
// that finds everything healthy makes no call that changes anything.
func TestSetRecordLeavesAnUnchangedRecordAlone(t *testing.T) {
	var puts, posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(apiResponse[[]Record]{Success: true, Result: []Record{
				{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: "1.2.3.4", TTL: 60},
			}})
		case r.Method == http.MethodPut:
			puts++
			_ = json.NewEncoder(w).Encode(apiResponse[Record]{Success: true, Result: Record{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: "1.2.3.4", TTL: 60}})
		case r.Method == http.MethodPost:
			posts++
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	c := New("tok")
	c.BaseURL = server.URL
	rec, changed, err := c.SetRecord(context.Background(), "zone1", "A", "vpn.example.com", "1.2.3.4", 60)
	if err != nil {
		t.Fatalf("setting the record failed: %v", err)
	}
	if changed {
		t.Fatal("an unchanged record was reported as changed")
	}
	if rec.ID != "rec1" {
		t.Fatalf("record id = %q", rec.ID)
	}
	if puts != 0 || posts != 0 {
		t.Fatalf("an unchanged record was written: %d puts, %d posts", puts, posts)
	}
}

// A record pointing elsewhere is updated, and a missing record is created.
func TestSetRecordUpdatesAndCreates(t *testing.T) {
	var puts, posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("name") == "vpn.example.com":
			_ = json.NewEncoder(w).Encode(apiResponse[[]Record]{Success: true, Result: []Record{
				{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: "1.2.3.4", TTL: 60},
			}})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(apiResponse[[]Record]{Success: true, Result: nil})
		case r.Method == http.MethodPut:
			puts++
			_ = json.NewEncoder(w).Encode(apiResponse[Record]{Success: true, Result: Record{ID: "rec1", Type: "A", Name: "vpn.example.com", Content: "5.6.7.8", TTL: 60}})
		case r.Method == http.MethodPost:
			posts++
			_ = json.NewEncoder(w).Encode(apiResponse[Record]{Success: true, Result: Record{ID: "rec2", Type: "A", Name: "new.example.com", Content: "5.6.7.8", TTL: 60}})
		}
	}))
	defer server.Close()

	c := New("tok")
	c.BaseURL = server.URL
	_, changed, err := c.SetRecord(context.Background(), "zone1", "A", "vpn.example.com", "5.6.7.8", 60)
	if err != nil {
		t.Fatalf("updating the record failed: %v", err)
	}
	if !changed || puts != 1 {
		t.Fatalf("the record was not updated: changed=%v puts=%d", changed, puts)
	}
	_, changed, err = c.SetRecord(context.Background(), "zone1", "A", "new.example.com", "5.6.7.8", 60)
	if err != nil {
		t.Fatalf("creating the record failed: %v", err)
	}
	if !changed || posts != 1 {
		t.Fatalf("the record was not created: changed=%v posts=%d", changed, posts)
	}
}

// A Cloudflare refusal is reported with its own message, not a bare status.
func TestACloudflareRefusalIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(apiResponse[[]Record]{Success: false, Errors: []apiError{{Code: 9109, Message: "Invalid access token"}}})
	}))
	defer server.Close()

	c := New("bad")
	c.BaseURL = server.URL
	if _, err := c.ListRecords(context.Background(), "zone1", "A", "vpn.example.com"); err == nil {
		t.Fatal("a Cloudflare refusal was not reported")
	} else if !strings.Contains(err.Error(), "Invalid access token") {
		t.Fatalf("the refusal does not carry Cloudflare's message: %v", err)
	}
}
