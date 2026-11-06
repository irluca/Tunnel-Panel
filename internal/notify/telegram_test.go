package notify

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

func (f fakeSettings) Bool(key string) bool {
	v, _ := f.values[key].(bool)
	return v
}

func (f fakeSettings) String(key string) string {
	v, _ := f.values[key].(string)
	return v
}

func (f fakeSettings) Int(key string) int64 {
	v, _ := f.values[key].(int64)
	return v
}

// A message is delivered to the Telegram API with the token in the path and
// the chat and the text in the body.
func TestSendDeliversTheMessage(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	n := New(fakeSettings{values: map[string]any{
		"notifications.telegram.enabled":   true,
		"notifications.telegram.bot_token": "123:abc",
		"notifications.telegram.chat_id":   "456",
		"notifications.telegram.tunnel_id": int64(0),
	}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.BaseURL = server.URL

	if err := n.Send(context.Background(), "the watchdog switched gre-a-1 to ESP"); err != nil {
		t.Fatalf("sending failed: %v", err)
	}
	if gotPath != "/bot123:abc/sendMessage" {
		t.Fatalf("path = %q, want the token in it", gotPath)
	}
	if gotBody["chat_id"] != "456" || gotBody["text"] != "the watchdog switched gre-a-1 to ESP" {
		t.Fatalf("body = %v", gotBody)
	}
}

// An unconfigured notifier is silent, not an error: the panel must work
// without Telegram.
func TestSendIsSilentWhenNotConfigured(t *testing.T) {
	n := New(fakeSettings{values: map[string]any{
		"notifications.telegram.enabled": false,
	}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.Send(context.Background(), "hello"); err != nil {
		t.Fatalf("an unconfigured notifier failed: %v", err)
	}
}

// A Telegram error is returned, so the caller can say the alert did not go
// out — but the caller never lets it stop the action the message was about.
func TestSendReportsATelegramError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Forbidden: bot was blocked"}`))
	}))
	defer server.Close()

	n := New(fakeSettings{values: map[string]any{
		"notifications.telegram.enabled":   true,
		"notifications.telegram.bot_token": "123:abc",
		"notifications.telegram.chat_id":   "456",
		"notifications.telegram.tunnel_id": int64(0),
	}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.BaseURL = server.URL

	if err := n.Send(context.Background(), "hello"); err == nil {
		t.Fatal("a Telegram refusal was not reported")
	}
}
