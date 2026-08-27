// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-blockstore.
//
// go-blockstore is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ha

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// logRecorder captures the controller's structured log so a test can wait on a
// message the controller emits.
//
// It exists for one narrow purpose: some branches of the shutdown's renewal
// loop have no other observable effect — they simply return — so a test that
// wanted to prove one was taken had to guess at scheduling. A log line the
// branch already deserves turns that guess into a barrier.
//
// It is a locked io.Writer behind slog's own text handler rather than a
// hand-written slog.Handler, because the handler interface takes slog.Record by
// value and this only ever needs the rendered text.
type logRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logRecorder) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// saw reports whether anything logged so far contains substr.
func (l *logRecorder) saw(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.buf.String(), substr)
}

const (
	testNode   = common.NodeID("node-a")
	testVolume = "vol1"
)

// observerLog records the statuses the controller reports, in order.
type observerLog struct {
	mu   sync.Mutex
	seen []Status
}

func (o *observerLog) observe(s Status) {
	o.mu.Lock()
	o.seen = append(o.seen, s)
	o.mu.Unlock()
}

// phases returns the phase of each recorded status.
func (o *observerLog) phases() []Phase {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]Phase, len(o.seen))
	for i := range o.seen {
		out[i] = o.seen[i].Phase
	}
	return out
}

// last returns the most recently recorded status. The manager unregisters the
// volume when it returns, so Controller.Status can no longer answer for it and
// the observer's record is what a shutdown test reads.
func (o *observerLog) last(t *testing.T) Status {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		t.Fatal("the observer recorded nothing")
	}
	return o.seen[len(o.seen)-1]
}

// everPrimary reports whether the controller EVER announced the primary role.
//
// It is the assertion a fencing test wants. Reading Status after the fact only
// says what is true now, and "we claimed primary for a moment and then took it
// back" is precisely the bug: an orchestrator watching the observer would have
// mounted on that announcement.
func (o *observerLog) everPrimary() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.seen {
		if o.seen[i].Primary {
			return true
		}
	}
	return false
}

// seenCopy returns a copy of every recorded status.
func (o *observerLog) seenCopy() []Status {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Status(nil), o.seen...)
}

// count returns how many statuses have been recorded.
func (o *observerLog) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.seen)
}

// rig wires a controller to a manual clock, a contract-faithful coordinator and
// a role-only provider, and runs one volume's manager in its own goroutine.
type rig struct {
	t     *testing.T
	clock *testClock
	coord *fakeCoordinator
	prov  *fakeProvider
	ctrl  *Controller
	obs   *observerLog
	logs  *logRecorder

	cancel context.CancelFunc
	exited chan error
}

// newRig builds the wiring without starting a manager. mutate, when non-nil,
// adjusts the config before New validates it.
func newRig(t *testing.T, prov *fakeProvider, mutate func(*Config)) *rig {
	t.Helper()

	r := &rig{
		t:     t,
		clock: newTestClock(),
		coord: newFakeCoordinator(),
		prov:  prov,
		obs:   &observerLog{},
		logs:  &logRecorder{},
	}

	cfg := Config{NodeID: testNode, Clock: r.clock}
	cfg.Observer = r.obs.observe
	cfg.Logger = slog.New(slog.NewTextHandler(r.logs, nil))
	if mutate != nil {
		mutate(&cfg)
	}

	ctrl, err := New(prov, r.coord, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ctrl = ctrl
	return r
}

// leaseKey returns the coordination key for a volume under this rig's config.
func (r *rig) leaseKey(volID string) string { return r.ctrl.Config().KeyPrefix + volID }

// start runs Manage for volID in its own goroutine.
func (r *rig) start(volID string) {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.exited = make(chan error, 1)
	go func() { r.exited <- r.ctrl.Manage(ctx, volID) }()
}

// stop cancels the manager and waits for Manage to return.
func (r *rig) stop() {
	r.t.Helper()
	if r.cancel == nil {
		return
	}
	r.cancel()
	select {
	case err := <-r.exited:
		if err != nil {
			r.t.Fatalf("Manage returned %v; a canceled manager stops cleanly", err)
		}
	case <-time.After(waitTimeout):
		r.t.Fatal("Manage did not return after its context was canceled")
	}
	r.cancel = nil
}

// stopPumpingTheClock cancels the manager and drains it while advancing the
// clock in the background.
//
// The shutdown path has timed waits of its own — the release retry spaces its
// attempts on the injected clock — so a manual clock that nobody advances would
// leave the manager parked forever and turn the test into a timeout. The pump
// starts only AFTER cancellation, so it cannot fire a renewal the test did not
// ask for.
func (r *rig) stopPumpingTheClock() {
	r.t.Helper()
	r.cancel()

	stop := make(chan struct{})
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			r.clock.Advance(r.ctrl.Config().RenewInterval)
			time.Sleep(pollInterval)
		}
	}()

	select {
	case err := <-r.exited:
		if err != nil {
			r.t.Errorf("Manage returned %v; a canceled manager stops cleanly", err)
		}
	case <-time.After(waitTimeout):
		r.t.Error("Manage did not return after its context was canceled")
	}
	close(stop)
	<-pumped
	r.cancel = nil
}

// status returns the managed volume's current status, failing if it is gone.
func (r *rig) status(volID string) Status {
	r.t.Helper()
	s, err := r.ctrl.Status(volID)
	if err != nil {
		r.t.Fatalf("Status(%q): %v", volID, err)
	}
	return s
}

// awaitPhase blocks until the volume reaches phase.
func (r *rig) awaitPhase(volID string, phase Phase) Status {
	r.t.Helper()
	var last Status
	waitFor(r.t, func() bool {
		s, err := r.ctrl.Status(volID)
		if err != nil {
			return false
		}
		last = s
		return s.Phase == phase
	}, "volume %q never reached phase %q (last: %+v)", volID, phase, &last)
	return last
}

// awaitPrimary blocks until the controller claims, or drops, the primary role.
func (r *rig) awaitPrimary(volID string, want bool) Status {
	r.t.Helper()
	var last Status
	waitFor(r.t, func() bool {
		s, err := r.ctrl.Status(volID)
		if err != nil {
			return false
		}
		last = s
		return s.Primary == want
	}, "volume %q never reported Primary=%v (last: %+v)", volID, want, &last)
	return last
}
