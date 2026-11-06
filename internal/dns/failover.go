package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

// Settings is the slice of the settings store the failover reads.
type Settings interface {
	Bool(key string) bool
	String(key string) string
	Int(key string) int64
	Get(key string) (any, bool)
}

// TunnelSource is the tunnel repository, for the candidate tunnels' endpoints.
type TunnelSource interface {
	ByID(ctx context.Context, id int64) (tunnel.Record, error)
}

// Snapshots is the monitor, for which candidate is healthy.
type Snapshots interface {
	Summary() []monitor.Snapshot
}

// Failover moves a DNS name between the foreign servers the panel's tunnels
// reach, in the order the operator listed them. The name points at the first
// candidate whose tunnel is Up; when that one goes down, the name moves to
// the next healthy one. When nothing is healthy it stays where it is —
// pointing at a dead server is no worse than pointing at the last known one,
// and flapping the record between dead servers helps nobody.
//
// Rotation is the same mechanism on a schedule: when a rotation interval is
// configured, the name moves to the next candidate in the list every
// interval, healthy or not, so the egress address changes on a schedule
// rather than only on failure.
type Failover struct {
	settings  Settings
	tunnels   TunnelSource
	snapshots Snapshots
	log       *slog.Logger
	// Now is the clock, for tests. It defaults to time.Now.
	Now func() time.Time
	// Client is the Cloudflare client, for tests. It defaults to one built
	// from the configured token.
	Client *Client
	// lastRotation is when the record last moved by rotation.
	lastRotation time.Time
	// rotationIndex is the candidate the record currently points at, for
	// rotation.
	rotationIndex int
}

// New returns a failover over the given settings, tunnels and monitor.
func NewFailover(settings Settings, tunnels TunnelSource, snapshots Snapshots, log *slog.Logger) *Failover {
	if log == nil {
		log = slog.Default()
	}
	return &Failover{settings: settings, tunnels: tunnels, snapshots: snapshots, log: log, Now: time.Now}
}

func (f *Failover) client() *Client {
	if f.Client != nil {
		return f.Client
	}
	return New(f.settings.String("dns.cloudflare.api_token"))
}

// candidateIDs reads the ordered list of tunnel ids the name may point at.
// The setting is a JSON array of ids; an empty list means no failover.
func (f *Failover) candidateIDs() []int64 {
	v, ok := f.settings.Get("dns.cloudflare.failover_tunnels")
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		f.log.Warn("the dns failover tunnel list is not a list of ids", "value", v)
		return nil
	}
	ids := make([]int64, 0, len(list))
	for _, item := range list {
		if n, ok := item.(float64); ok {
			ids = append(ids, int64(n))
		}
	}
	return ids
}

// Check moves the record to the first healthy candidate, if it is not
// already there. It does nothing when failover is disabled or unconfigured.
// It returns the record's content after the check, and whether it changed.
func (f *Failover) Check(ctx context.Context) (string, bool, error) {
	if !f.settings.Bool("dns.cloudflare.enabled") {
		return "", false, nil
	}
	zoneID := f.settings.String("dns.cloudflare.zone_id")
	name := f.settings.String("dns.cloudflare.record_name")
	recordType := f.settings.String("dns.cloudflare.record_type")
	if zoneID == "" || name == "" {
		return "", false, nil
	}
	if recordType == "" {
		recordType = "A"
	}
	ttl := int(f.settings.Int("dns.cloudflare.ttl"))
	if ttl <= 0 {
		ttl = 60
	}

	// Rotation first: on a schedule the record moves to the next candidate,
	// whatever its health. Failover then applies only when the record's
	// current target is unhealthy.
	if interval := f.settings.Int("dns.cloudflare.rotation_interval_seconds"); interval > 0 {
		if f.Now().Sub(f.lastRotation) >= time.Duration(interval)*time.Second {
			if content, changed, err := f.rotate(ctx, zoneID, recordType, name, ttl); err != nil {
				return "", false, err
			} else if changed {
				f.lastRotation = f.Now()
				return content, true, nil
			}
		}
	}

	ids := f.candidateIDs()
	if len(ids) == 0 {
		return "", false, nil
	}
	healthy := f.healthyEndpoints(ctx, ids)
	if len(healthy) == 0 {
		f.log.Warn("dns failover: no candidate tunnel is healthy; the record stays where it is", "name", name)
		return "", false, nil
	}
	target := healthy[0]
	rec, changed, err := f.client().SetRecord(ctx, zoneID, recordType, name, target, ttl)
	if err != nil {
		return "", false, fmt.Errorf("pointing %s at %s: %w", name, target, err)
	}
	if changed {
		f.log.Info("dns failover moved the record", "name", name, "content", target)
	}
	return rec.Content, changed, nil
}

// rotate moves the record to the next candidate in the list, wrapping
// around. It is the scheduled rotation: the egress address changes on a
// schedule rather than only on failure.
func (f *Failover) rotate(ctx context.Context, zoneID, recordType, name string, ttl int) (string, bool, error) {
	ids := f.candidateIDs()
	if len(ids) == 0 {
		return "", false, nil
	}
	f.rotationIndex = (f.rotationIndex + 1) % len(ids)
	rec, err := f.tunnels.ByID(ctx, ids[f.rotationIndex])
	if err != nil {
		return "", false, fmt.Errorf("reading the rotation candidate: %w", err)
	}
	target := endpointIP(rec.RemoteEndpoint)
	if target == "" {
		return "", false, fmt.Errorf("the rotation candidate %s has no remote endpoint", rec.InterfaceName)
	}
	updated, changed, err := f.client().SetRecord(ctx, zoneID, recordType, name, target, ttl)
	if err != nil {
		return "", false, fmt.Errorf("rotating %s to %s: %w", name, target, err)
	}
	if changed {
		f.log.Info("dns rotation moved the record", "name", name, "content", target)
	}
	return updated.Content, changed, nil
}

// healthyEndpoints returns, in the candidate order, the remote endpoints of
// the tunnels whose monitor state is Up.
func (f *Failover) healthyEndpoints(ctx context.Context, ids []int64) []string {
	states := map[int64]int64{}
	for _, snap := range f.snapshots.Summary() {
		states[snap.TunnelID] = snap.MonitorStateID
	}
	var healthy []string
	for _, id := range ids {
		if states[id] != model.MonitorStateUp {
			continue
		}
		rec, err := f.tunnels.ByID(ctx, id)
		if err != nil {
			f.log.Warn("dns failover could not read a candidate tunnel", "tunnel_id", id, "error", err)
			continue
		}
		if ip := endpointIP(rec.RemoteEndpoint); ip != "" {
			healthy = append(healthy, ip)
		}
	}
	return healthy
}

// endpointIP returns the IP of a remote endpoint, which may carry a port or
// a scheme. An endpoint that is not an IP is not a DNS answer.
func endpointIP(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}
