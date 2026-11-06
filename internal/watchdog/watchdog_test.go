package watchdog

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

type fakeSnapshots struct {
	snaps []monitor.Snapshot
}

func (f *fakeSnapshots) Summary() []monitor.Snapshot { return f.snaps }

type fakeTunnels struct {
	records []tunnel.Record
}

func (f *fakeTunnels) List(ctx context.Context) ([]tunnel.Record, error) { return f.records, nil }

type fakeSwitcher struct {
	calls []switchCall
	fail  bool
}

type switchCall struct {
	id     int64
	target int64
}

func (f *fakeSwitcher) Switch(ctx context.Context, id int64, targetTypeID int64, espKey *string, clientIP string) (tunnel.Result, error) {
	f.calls = append(f.calls, switchCall{id, targetTypeID})
	if f.fail {
		return tunnel.Result{}, errSwitchFailed
	}
	return tunnel.Result{}, nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errSwitchFailed errString = "the switch failed"

type fakeSettings struct {
	bools map[string]bool
	ints  map[string]int64
}

func (f *fakeSettings) Bool(key string) bool { return f.bools[key] }
func (f *fakeSettings) Int(key string) int64 { return f.ints[key] }

func defaultSettings(enabled bool) *fakeSettings {
	return &fakeSettings{
		bools: map[string]bool{"watchdog.enabled": enabled},
		ints: map[string]int64{
			"watchdog.down_seconds":                DefaultDownSeconds,
			"watchdog.min_switch_interval_seconds": DefaultMinSwitchIntervalSeconds,
			"watchdog.max_switches":                DefaultMaxSwitches,
			"watchdog.window_seconds":              DefaultWindowSeconds,
		},
	}
}

func downSnapshot(id int64, since time.Time) monitor.Snapshot {
	return monitor.Snapshot{
		TunnelID:       id,
		InterfaceName:  "gre-a-1",
		MonitorStateID: model.MonitorStateDown,
		State:          "Down",
		Since:          since,
	}
}

func greRecord(id int64) tunnel.Record {
	return tunnel.Record{Tunnel: model.Tunnel{TunnelID: id, TunnelTypeID: model.TunnelTypeGRE, InterfaceName: "gre-a-1"}}
}

func TestDownForAMinuteSwitches(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-61*time.Second))}}
	sw := &fakeSwitcher{}
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return now },
	})
	w.tick(context.Background())
	if len(sw.calls) != 1 {
		t.Fatalf("switches = %d, want 1", len(sw.calls))
	}
	if sw.calls[0].target != model.TunnelTypeESP {
		t.Fatalf("target = %d, want ESP", sw.calls[0].target)
	}
}

func TestDownForLessThanAMinuteDoesNotSwitch(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-30*time.Second))}}
	sw := &fakeSwitcher{}
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return now },
	})
	w.tick(context.Background())
	if len(sw.calls) != 0 {
		t.Fatalf("switches = %d, want 0", len(sw.calls))
	}
}

func TestDegradedNeverSwitches(t *testing.T) {
	now := time.Now()
	snap := downSnapshot(1, now.Add(-10*time.Minute))
	snap.MonitorStateID = model.MonitorStateDegraded
	snap.State = "Degraded"
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{snap}}
	sw := &fakeSwitcher{}
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return now },
	})
	w.tick(context.Background())
	if len(sw.calls) != 0 {
		t.Fatalf("switches = %d, want 0", len(sw.calls))
	}
}

func TestNonCarrierTunnelNeverSwitches(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-10*time.Minute))}}
	sw := &fakeSwitcher{}
	rec := greRecord(1)
	rec.TunnelTypeID = model.TunnelTypeGRETAP
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{rec}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return now },
	})
	w.tick(context.Background())
	if len(sw.calls) != 0 {
		t.Fatalf("switches = %d, want 0", len(sw.calls))
	}
}

func TestDisabledWatchdogNeverSwitches(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-10*time.Minute))}}
	sw := &fakeSwitcher{}
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(false),
		Log:       slog.Default(),
		Now:       func() time.Time { return now },
	})
	w.tick(context.Background())
	if len(sw.calls) != 0 {
		t.Fatalf("switches = %d, want 0", len(sw.calls))
	}
}

func TestBreakerStopsAfterThreeSwitches(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-10*time.Minute))}}
	sw := &fakeSwitcher{}
	clock := now
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return clock },
	})
	ctx := context.Background()
	// Three switches, spaced past the minimum interval.
	for i := 0; i < 3; i++ {
		w.tick(ctx)
		clock = clock.Add(4 * time.Minute)
	}
	if len(sw.calls) != 3 {
		t.Fatalf("switches = %d, want 3", len(sw.calls))
	}
	// A fourth, still inside the window, is refused and the breaker is
	// recorded.
	w.tick(ctx)
	if len(sw.calls) != 3 {
		t.Fatalf("switches = %d, want 3 (breaker)", len(sw.calls))
	}
	if len(w.Breaker()) != 1 {
		t.Fatalf("breaker reports %d tunnels, want 1", len(w.Breaker()))
	}
	// Once the window passes, switching resumes.
	clock = clock.Add(16 * time.Minute)
	w.tick(ctx)
	if len(sw.calls) != 4 {
		t.Fatalf("switches = %d, want 4 after the window", len(sw.calls))
	}
}

func TestMinIntervalBetweenSwitches(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-10*time.Minute))}}
	sw := &fakeSwitcher{}
	clock := now
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return clock },
	})
	ctx := context.Background()
	w.tick(ctx)
	clock = clock.Add(60 * time.Second)
	w.tick(ctx)
	if len(sw.calls) != 1 {
		t.Fatalf("switches = %d, want 1 (min interval)", len(sw.calls))
	}
	clock = clock.Add(3 * time.Minute)
	w.tick(ctx)
	if len(sw.calls) != 2 {
		t.Fatalf("switches = %d, want 2 after the interval", len(sw.calls))
	}
}

func TestFailedSwitchCountsTowardTheBreaker(t *testing.T) {
	now := time.Now()
	snaps := &fakeSnapshots{snaps: []monitor.Snapshot{downSnapshot(1, now.Add(-10*time.Minute))}}
	sw := &fakeSwitcher{fail: true}
	clock := now
	w := New(Deps{
		Snapshots: snaps,
		Tunnels:   &fakeTunnels{records: []tunnel.Record{greRecord(1)}},
		Switch:    sw,
		Settings:  defaultSettings(true),
		Log:       slog.Default(),
		Now:       func() time.Time { return clock },
	})
	ctx := context.Background()
	// Three failed attempts, spaced past the minimum interval, trip the
	// breaker: retrying a switch that keeps failing only interrupts the
	// tunnel for nothing.
	for i := 0; i < 3; i++ {
		w.tick(ctx)
		clock = clock.Add(4 * time.Minute)
	}
	if len(sw.calls) != 3 {
		t.Fatalf("attempts = %d, want 3", len(sw.calls))
	}
	w.tick(ctx)
	if len(sw.calls) != 3 {
		t.Fatalf("attempts = %d, want 3 (breaker)", len(sw.calls))
	}
}
