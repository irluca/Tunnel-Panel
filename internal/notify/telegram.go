// Package notify sends the operator a message when the panel acts on its
// own — the watchdog switching a carrier, or its breaker tripping. The
// message goes to Telegram, and it can go through a tunnel rather than the
// direct internet: when the server's own path is filtered, the tunnel is
// often the only way out, and an alert that cannot leave the server is no
// alert at all.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/drs/gre-panel/internal/tunnel"
)

// Settings is the slice of the settings store the notifier reads.
type Settings interface {
	Bool(key string) bool
	String(key string) string
	Int(key string) int64
}

// TunnelSource is the tunnel repository, for the inner address of the tunnel
// a notification is routed through.
type TunnelSource interface {
	ByID(ctx context.Context, id int64) (tunnel.Record, error)
}

// Notifier sends Telegram messages, optionally through a tunnel.
type Notifier struct {
	settings Settings
	tunnels  TunnelSource
	log      *slog.Logger
	client   *http.Client
	// BaseURL is the Telegram API root. It defaults to the real one; tests
	// point it at a local server.
	BaseURL string
}

// New returns a notifier over the given settings and tunnel source.
func New(settings Settings, tunnels TunnelSource, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{settings: settings, tunnels: tunnels, log: log,
		client:  &http.Client{Timeout: 15 * time.Second},
		BaseURL: "https://api.telegram.org"}
}

// Send delivers a message to the configured Telegram chat. It does nothing
// when notifications are disabled, or when the token or the chat is not
// configured — an unconfigured notifier is silent, not an error, because the
// panel must work without Telegram. A delivery failure is logged and
// returned so the caller can say so, but it never stops the action the
// message was about.
func (n *Notifier) Send(ctx context.Context, text string) error {
	if !n.settings.Bool("notifications.telegram.enabled") {
		return nil
	}
	token := n.settings.String("notifications.telegram.bot_token")
	chatID := n.settings.String("notifications.telegram.chat_id")
	if token == "" || chatID == "" {
		n.log.Debug("telegram notifications are enabled but the token or the chat is not configured")
		return nil
	}

	client, err := n.clientFor(ctx)
	if err != nil {
		return fmt.Errorf("building the telegram client: %w", err)
	}

	body, err := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	if err != nil {
		return err
	}
	endpoint := n.BaseURL + "/bot" + url.PathEscape(token) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending the telegram message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram answered %s", resp.Status)
	}
	return nil
}

// clientFor returns the HTTP client the message goes out on. When a tunnel
// is configured, the connection is bound to that tunnel's inner address, so
// the kernel routes it through the tunnel and out the far end; when no
// tunnel is configured, or the tunnel cannot be read, the message goes out
// directly.
func (n *Notifier) clientFor(ctx context.Context) (*http.Client, error) {
	tunnelID := n.settings.Int("notifications.telegram.tunnel_id")
	if tunnelID <= 0 {
		return n.client, nil
	}
	rec, err := n.tunnels.ByID(ctx, tunnelID)
	if err != nil {
		n.log.Warn("the tunnel configured for telegram notifications could not be read; sending directly",
			"tunnel_id", tunnelID, "error", err)
		return n.client, nil
	}
	inner := primaryAddress(rec)
	if inner == "" {
		n.log.Warn("the tunnel configured for telegram notifications has no inner address; sending directly",
			"tunnel_id", tunnelID)
		return n.client, nil
	}
	ip := net.ParseIP(inner)
	if ip == nil {
		n.log.Warn("the tunnel configured for telegram notifications has an unusable inner address; sending directly",
			"tunnel_id", tunnelID, "address", inner)
		return n.client, nil
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 10 * time.Second}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}, nil
}

// primaryAddress returns the tunnel's primary inner address, which is the
// address the tunnel itself is numbered with and the one a connection bound
// to it leaves through.
func primaryAddress(rec tunnel.Record) string {
	for _, addr := range rec.Addresses {
		if addr.IsPrimary {
			return addr.Address
		}
	}
	if len(rec.Addresses) > 0 {
		return rec.Addresses[0].Address
	}
	return ""
}
