// Package cluster watches the other panel instances this panel is deployed
// with. Each server runs its own panel; the cluster is the set of them, and
// this is the view of it from here: which peers answer, which do not, and
// what each one reports about itself. It is a view, not a control plane —
// one panel never changes another's tunnels, and a peer that does not answer
// is reported as down rather than retried forever.
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Peer is one panel instance in the cluster, as the operator listed it.
type Peer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// PeerStatus is what a peer answered, or that it did not.
type PeerStatus struct {
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Reachable     bool      `json:"reachable"`
	Status        string    `json:"status,omitempty"`
	Version       string    `json:"version,omitempty"`
	UptimeSeconds int64     `json:"uptime_seconds,omitempty"`
	Error         string    `json:"error,omitempty"`
	CheckedAt     time.Time `json:"checked_at"`
}

type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	SetupRequired bool   `json:"setup_required"`
}

// Settings is the slice of the settings store the cluster reads.
type Settings interface {
	Get(key string) (any, bool)
}

// Checker polls the cluster's peers.
type Checker struct {
	settings Settings
	log      *slog.Logger
	client   *http.Client
}

// New returns a checker over the given settings.
func New(settings Settings, log *slog.Logger) *Checker {
	if log == nil {
		log = slog.Default()
	}
	return &Checker{settings: settings, log: log, client: &http.Client{Timeout: 5 * time.Second}}
}

// Peers returns the configured peers, in the order the operator listed them.
func (c *Checker) Peers() []Peer {
	v, ok := c.settings.Get("cluster.peers")
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		c.log.Warn("the cluster peer list is not a list", "value", v)
		return nil
	}
	peers := make([]Peer, 0, len(list))
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		rawURL, _ := obj["url"].(string)
		if name == "" || rawURL == "" {
			continue
		}
		peers = append(peers, Peer{Name: name, URL: rawURL})
	}
	return peers
}

// Check polls every peer's health endpoint and reports what each answered.
// A peer that does not answer in time, or answers an error, is reported as
// unreachable with the reason — the cluster view must say a peer is down
// rather than leave it blank.
func (c *Checker) Check(ctx context.Context) []PeerStatus {
	peers := c.Peers()
	out := make([]PeerStatus, 0, len(peers))
	for _, peer := range peers {
		out = append(out, c.checkOne(ctx, peer))
	}
	return out
}

func (c *Checker) checkOne(ctx context.Context, peer Peer) PeerStatus {
	status := PeerStatus{Name: peer.Name, URL: peer.URL, CheckedAt: time.Now()}
	endpoint, err := healthURL(peer.URL)
	if err != nil {
		status.Error = fmt.Sprintf("the peer url is not usable: %v", err)
		return status
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	resp, err := c.client.Do(req)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if resp.StatusCode >= 300 {
		status.Error = fmt.Sprintf("the peer answered %s", resp.Status)
		return status
	}
	var health healthResponse
	if err := json.Unmarshal(raw, &health); err != nil {
		status.Error = fmt.Sprintf("the peer's health answer could not be read: %v", err)
		return status
	}
	status.Reachable = true
	status.Status = health.Status
	status.Version = health.Version
	status.UptimeSeconds = health.UptimeSeconds
	if health.SetupRequired {
		status.Error = "the peer has not finished setup"
	}
	return status
}

// healthURL is the peer's health endpoint. The operator gives the panel's
// base URL (with or without a web path); the health endpoint lives at the
// API root, which is the base path plus /api/v1.
func healthURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("a peer url needs a scheme and a host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/system/health"
	return u.String(), nil
}
