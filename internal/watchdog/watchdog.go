// Package watchdog watches the monitor's verdicts and switches a tunnel's
// carrier when it has been down too long — the automatic failover.
//
// A tunnel that is merely Degraded is never switched: partial loss is not a
// dead carrier. A tunnel must be continuously Down for the configured
// duration (a minute by default) before the carrier changes, so a brief
// blip does not rebuild a working tunnel.
//
// The switch itself is the tunnel service's Switch, with its verified
// rollback: if the new carrier does not verify, the previous one comes back.
// The watchdog adds a circuit breaker on top of that, because a carrier that
// fails twice is a broken path, not a carrier problem, and switching it again
// only interrupts the tunnel for nothing. The breaker allows one switch per
// tunnel at most every three minutes and at most three in fifteen minutes;
// while it is tripped the tunnel is left alone and the reason is recorded.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

// Defaults for the watchdog. They are the same numbers the Rahyaab healer
// settled on: a minute down before switching, three minutes between switches,
// three switches in a fifteen-minute window.
const (
	DefaultDownSeconds              = int64(60)
	DefaultMinSwitchIntervalSeconds = int64(180)
	DefaultMaxSwitches              = int64(3)
	DefaultWindowSeconds            = int64(900)

	// tickInterval is how often the watchdog looks at the monitor's verdicts.
	// The decision is time-based (how long the tunnel has been Down), so the
	// tick only sets how promptly a switch follows a verdict.
	tickInterval = 10 * time.Second
)

// Settings is the subset of the panel's settings the watchdog reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
}

// TunnelSource lists the tunnels, so the watchdog knows each one's carrier.
type TunnelSource interface {
	List(ctx context.Context) ([]tunnel.Record, error)
}

// Switcher changes a tunnel's carrier. It is the tunnel service's Switch.
type Switcher interface {
	Switch(ctx context.Context, id int64, targetTypeID int64, espKey *string, clientIP string) (tunnel.Result, error)
}

// Snapshots is the monitor's current verdict for every tunnel.
type Snapshots interface {
	Summary() []monitor.Snapshot
}

// Deps is everything the watchdog needs.
// Notifier is what the watchdog tells when it acts on its own: a carrier
// switch, or a breaker trip. It is an interface so the watchdog can be
// tested without a Telegram token.
type Notifier interface {
	Send(ctx context.Context, text string) error
}

type Deps struct {
	Snapshots Snapshots
	Tunnels   TunnelSource
	Switch    Switcher
	Settings  Settings
	// Notify is told when the watchdog switches a carrier or its breaker
	// trips. Nil means nobody is told.
	Notify Notifier
	Log    *slog.Logger
	// Now is the clock, for tests. It defaults to time.Now.
	Now func() time.Time
}

// Watchdog owns the failover loop.
type Watchdog struct {
	snapshots Snapshots
	tunnels   TunnelSource
	switcher  Switcher
	settings  Settings
	notify    Notifier
	log       *slog.Logger
	now       func() time.Time

	mu sync.Mutex
	// lastSwitch is when a tunnel was last switched (an attempt, not only a
	// success: a failed switch is still an interruption, and retrying it
	// immediately would only interrupt again).
	lastSwitch map[int64]time.Time
	// switchTimes is the attempts in the current breaker window.
	switchTimes map[int64][]time.Time
	// breakerTripped is when the breaker stopped switching a tunnel, and why.
	breakerTripped map[int64]breakerTrip
}

type breakerTrip struct {
	at     time.Time
	reason string
}

// New returns a watchdog that does nothing until Start is called.
func New(d Deps) *Watchdog {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Watchdog{
		snapshots:      d.Snapshots,
		tunnels:        d.Tunnels,
		switcher:       d.Switch,
		settings:       d.Settings,
		notify:         d.Notify,
		log:            log,
		now:            now,
		lastSwitch:     map[int64]time.Time{},
		switchTimes:    map[int64][]time.Time{},
		breakerTripped: map[int64]breakerTrip{},
	}
}

// Start runs the failover loop until ctx is cancelled.
func (w *Watchdog) Start(ctx context.Context) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick looks at every tunnel's verdict once and switches the ones that have
// been down long enough and whose breaker allows it.
func (w *Watchdog) tick(ctx context.Context) {
	if !w.settings.Bool("watchdog.enabled") {
		return
	}
	records, err := w.tunnels.List(ctx)
	if err != nil {
		w.log.Error("watchdog could not list tunnels", "error", err)
		return
	}
	byID := make(map[int64]tunnel.Record, len(records))
	for _, rec := range records {
		byID[rec.TunnelID] = rec
	}
	now := w.now()
	downSeconds := time.Duration(w.settings.Int("watchdog.down_seconds")) * time.Second
	for _, snap := range w.snapshots.Summary() {
		if snap.MonitorStateID != model.MonitorStateDown {
			continue
		}
		rec, ok := byID[snap.TunnelID]
		if !ok {
			continue
		}
		target, ok := otherCarrier(rec.TunnelTypeID)
		if !ok {
			// Only GRE and ESP have a carrier to switch to.
			continue
		}
		if snap.Since.IsZero() || now.Sub(snap.Since) < downSeconds {
			continue
		}
		w.consider(ctx, rec, target, now)
	}
}

// consider switches one tunnel if its breaker allows it, and records the
// attempt before it starts, so a concurrent tick cannot switch the same
// tunnel twice. The switch itself runs outside the lock: it rebuilds and
// verifies, which takes seconds, and the tick is not latency-sensitive.
func (w *Watchdog) consider(ctx context.Context, rec tunnel.Record, target int64, now time.Time) {
	w.mu.Lock()
	minInterval := time.Duration(w.settings.Int("watchdog.min_switch_interval_seconds")) * time.Second
	maxSwitches := w.settings.Int("watchdog.max_switches")
	window := time.Duration(w.settings.Int("watchdog.window_seconds")) * time.Second

	if last, ok := w.lastSwitch[rec.TunnelID]; ok && now.Sub(last) < minInterval {
		w.mu.Unlock()
		return
	}
	// Count the attempts still inside the window.
	kept := w.switchTimes[rec.TunnelID][:0]
	for _, at := range w.switchTimes[rec.TunnelID] {
		if now.Sub(at) < window {
			kept = append(kept, at)
		}
	}
	w.switchTimes[rec.TunnelID] = kept
	if int64(len(kept)) >= maxSwitches {
		if _, tripped := w.breakerTripped[rec.TunnelID]; !tripped {
			w.breakerTripped[rec.TunnelID] = breakerTrip{at: now,
				reason: "too many switches in the window"}
			w.log.Warn("watchdog breaker tripped: leaving the tunnel alone",
				"tunnel", rec.InterfaceName, "switches", len(kept), "window", window)
			w.tell(ctx, fmt.Sprintf("The watchdog stopped switching %s: %d switches in %s, so the breaker tripped and the tunnel is left alone.",
				rec.InterfaceName, len(kept), window))
		}
		w.mu.Unlock()
		return
	}
	delete(w.breakerTripped, rec.TunnelID)

	w.lastSwitch[rec.TunnelID] = now
	w.switchTimes[rec.TunnelID] = append(w.switchTimes[rec.TunnelID], now)
	w.mu.Unlock()

	_, err := w.switcher.Switch(ctx, rec.TunnelID, target, nil, "")
	if err != nil {
		w.log.Error("watchdog switch failed; the previous carrier was restored",
			"tunnel", rec.InterfaceName, "target", target, "error", err)
		w.tell(ctx, fmt.Sprintf("The watchdog tried to switch %s to %s and failed; the previous carrier was restored. (%v)",
			rec.InterfaceName, model.TunnelTypeKind(target), err))
		return
	}
	w.log.Info("watchdog switched the carrier",
		"tunnel", rec.InterfaceName, "target", target)
	w.tell(ctx, fmt.Sprintf("The watchdog switched %s to %s after it was down for a minute.",
		rec.InterfaceName, model.TunnelTypeKind(target)))
}

// tell sends a message through the notifier, if one is wired. A delivery
// failure is logged and swallowed: the notification is about the action, and
// a failed notification must never make the action look failed.
func (w *Watchdog) tell(ctx context.Context, text string) {
	if w.notify == nil {
		return
	}
	if err := w.notify.Send(ctx, text); err != nil {
		w.log.Warn("sending the watchdog notification failed", "error", err)
	}
}

// otherCarrier returns the carrier a tunnel switches to, and whether it has
// one. Only GRE and ESP switch; every other kind is a tunnel in its own right.
func otherCarrier(typeID int64) (int64, bool) {
	switch typeID {
	case model.TunnelTypeGRE:
		return model.TunnelTypeESP, true
	case model.TunnelTypeESP:
		return model.TunnelTypeGRE, true
	}
	return 0, false
}

// Breaker returns, for each tunnel the breaker has stopped switching, when it
// tripped and why. It is what the operator reads to find out why a tunnel
// that is down was left alone.
func (w *Watchdog) Breaker() map[int64]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[int64]string, len(w.breakerTripped))
	for id, trip := range w.breakerTripped {
		out[id] = trip.reason
	}
	return out
}
