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
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// fakeCoordinator is an in-memory common.Coordinator written to the contract in
// pkg/common/coordinator.go, not to what these tests happen to need.
//
// A fixture that can emit an outcome the real contract cannot produce is a
// defect in the fixture, so every rule the contract states is implemented here
// rather than approximated:
//
//   - AcquireLease is exclusive and FAIL-FAST. A contended key is refused with
//     common.ErrLeaseHeld wrapped around a typed error carrying the key, so
//     errors.Is and errors.As both work — the shape both real implementations
//     produce (*sdk.LeaseHeldError clustered, coordination.LeaseHeldError
//     standalone).
//   - ttl is rounded UP to whole seconds with a one-second floor.
//   - The acknowledged deadline is HARD: expiry closes Done and deletes the
//     bound key.
//   - Renew after the lease is over returns a lease-lost error and NEVER nil,
//     and does not resurrect the lease.
//   - Release is idempotent only once it has SUCCEEDED. A release the backend
//     refuses leaves Done open and the key bound.
//   - CompareAndSwap's nil expect is create-only; a non-nil expect — an empty
//     slice included — requires the key to EXIST.
//   - Get returns (nil, nil) for an absent key and a non-nil zero-length slice
//     for a present empty value.
//   - Delete of an absent key is nil, and deleting a leased key removes the
//     ownership signal without ending the lease.
//   - A Watch channel's close is the only end-of-watch signal.
//
// Expiry has two entry points and ONE implementation. A real TTL elapse fires
// expireLocked through a timer; expireNow fires the same function directly, so
// a test can put a lease past its deadline without waiting out a second. The
// deterministic hook cannot therefore produce a state the timer path could not:
// there is only one path.
type fakeCoordinator struct {
	mu       sync.Mutex
	store    map[string][]byte
	leases   map[string]*fakeLease
	watchers map[*fakeWatcher]struct{}
	calls    []string

	// Fault injection. Each is consulted before the operation acts, so an
	// injected failure leaves the store untouched, which is what an
	// operational failure at the backend looks like.
	acquireErr error
	renewErr   error
	releaseErr error

	// releaseErrRemaining, when positive, makes releaseErr apply to that many
	// further calls and then stop. It models a backend that is briefly
	// unreachable, which is the case the release retry exists for; a sticky
	// error would only ever exercise the give-up branch.
	releaseErrRemaining int

	// acquireHook and renewHook run inside their calls, with the coordinator
	// lock NOT held. They are the barriers tests use to interleave an
	// acquisition or a renewal with something else — advancing the clock to
	// model a slow round trip, or holding the call open across a fence.
	acquireHook func(key string)
	renewHook   func(key string)
}

// leaseMarker is the value bound under a leased key. The key's existence is the
// ownership signal, and both real implementations store a non-empty marker so a
// held lease's Get stays distinguishable from an absent key's.
var leaseMarker = []byte{1}

// errFakeLeaseLost is what a renewal of a lease that is already over reports.
var errFakeLeaseLost = errors.New("lease lost before renewal")

// fakeLeaseHeldError carries the contended key under common.ErrLeaseHeld, the
// way the real implementations carry theirs.
type fakeLeaseHeldError struct{ Key string }

func (e *fakeLeaseHeldError) Error() string { return "lease key already held: " + e.Key }

var _ common.Coordinator = (*fakeCoordinator)(nil)

func newFakeCoordinator() *fakeCoordinator {
	return &fakeCoordinator{
		store:    make(map[string][]byte),
		leases:   make(map[string]*fakeLease),
		watchers: make(map[*fakeWatcher]struct{}),
	}
}

// record notes a contract method call. The controller's call set is part of its
// design — it uses leases and nothing else — so the recording is an assertion
// surface, not diagnostics.
func (c *fakeCoordinator) record(op string) {
	c.mu.Lock()
	c.calls = append(c.calls, op)
	c.mu.Unlock()
}

// recorded returns the ops seen so far.
func (c *fakeCoordinator) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// setAcquireErr makes the next and every subsequent AcquireLease fail with an
// operational error — not a contended key.
func (c *fakeCoordinator) setAcquireErr(err error) {
	c.mu.Lock()
	c.acquireErr = err
	c.mu.Unlock()
}

// setRenewErr makes Renew fail without ending the lease, which is exactly the
// unacknowledged renewal the contract warns about.
func (c *fakeCoordinator) setRenewErr(err error) {
	c.mu.Lock()
	c.renewErr = err
	c.mu.Unlock()
}

// setReleaseErr makes Release fail. A refused release is not a release: Done
// stays open and the key stays bound.
func (c *fakeCoordinator) setReleaseErr(err error) {
	c.mu.Lock()
	c.releaseErr = err
	c.mu.Unlock()
}

// setReleaseErrTimes makes the next n releases fail and the ones after succeed.
func (c *fakeCoordinator) setReleaseErrTimes(err error, n int) {
	c.mu.Lock()
	c.releaseErr = err
	c.releaseErrRemaining = n
	c.mu.Unlock()
}

// setAcquireHook installs the acquisition barrier. It runs without the lock held.
func (c *fakeCoordinator) setAcquireHook(fn func(key string)) {
	c.mu.Lock()
	c.acquireHook = fn
	c.mu.Unlock()
}

// setRenewHook installs the renewal barrier. It runs without the lock held.
func (c *fakeCoordinator) setRenewHook(fn func(key string)) {
	c.mu.Lock()
	c.renewHook = fn
	c.mu.Unlock()
}

// expireNow puts the lease bound to key past its deadline, through the same
// function its timer would call.
func (c *fakeCoordinator) expireNow(key string) bool {
	c.mu.Lock()
	l, ok := c.leases[key]
	c.mu.Unlock()
	if !ok {
		return false
	}
	l.expire()
	return true
}

// leaseFor returns the lease currently bound to key, or nil. It lets a test
// hold on to the lease object across an expiry that would otherwise leave it
// unreachable by key.
func (c *fakeCoordinator) leaseFor(key string) common.Lease {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.leases[key]
	if !ok {
		return nil
	}
	return l
}

// held reports whether key is currently bound.
func (c *fakeCoordinator) held(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.store[key]
	return ok
}

// normalizeTTL rounds ttl up to whole seconds with a one-second floor, which is
// the granularity the contract promises.
func normalizeTTL(ttl time.Duration) time.Duration {
	if ttl <= time.Second {
		return time.Second
	}
	rounded := ttl.Truncate(time.Second)
	if rounded < ttl {
		rounded += time.Second
	}
	return rounded
}

func (c *fakeCoordinator) AcquireLease(ctx context.Context, key string, ttl time.Duration) (common.Lease, error) {
	c.record("AcquireLease")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	hook := c.acquireHook
	injected := c.acquireErr
	c.mu.Unlock()

	if injected != nil {
		return nil, injected
	}
	if hook != nil {
		hook(key)
	}
	// Re-checked after the hook: a backend RPC does not complete against a
	// context that was canceled while it was in flight, so neither may this.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	effective := normalizeTTL(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, taken := c.store[key]; taken {
		return nil, fmt.Errorf("%w: %w", common.ErrLeaseHeld, &fakeLeaseHeldError{Key: key})
	}

	l := &fakeLease{coord: c, key: key, ttl: effective, done: make(chan struct{})}
	c.putLocked(key, leaseMarker)
	c.leases[key] = l
	l.timer = time.AfterFunc(effective, l.expire)
	return l, nil
}

func (c *fakeCoordinator) Get(ctx context.Context, key string) ([]byte, error) {
	c.record("Get")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	val, ok := c.store[key]
	if !ok {
		return nil, nil
	}
	return cloneValue(val), nil
}

func (c *fakeCoordinator) Put(ctx context.Context, key string, val []byte) error {
	c.record("Put")
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, val)
	return nil
}

func (c *fakeCoordinator) Delete(ctx context.Context, key string) error {
	c.record("Delete")
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteLocked(key)
	return nil
}

func (c *fakeCoordinator) CompareAndSwap(ctx context.Context, key string, expect, set []byte) (bool, error) {
	c.record("CompareAndSwap")
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, exists := c.store[key]
	if expect == nil {
		if exists {
			return false, nil
		}
	} else if !exists || !bytes.Equal(cur, expect) {
		return false, nil
	}
	c.putLocked(key, set)
	return true, nil
}

func (c *fakeCoordinator) Watch(ctx context.Context, prefix string) (<-chan common.Event, error) {
	c.record("Watch")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &fakeWatcher{prefix: prefix, out: make(chan common.Event), wake: make(chan struct{}, 1)}
	c.mu.Lock()
	c.watchers[w] = struct{}{}
	c.mu.Unlock()
	go w.pump(ctx, c)
	return w.out, nil
}

// putLocked stores a copy of val and publishes the change.
func (c *fakeCoordinator) putLocked(key string, val []byte) {
	stored := cloneValue(val)
	c.store[key] = stored
	c.publishLocked(common.Event{Type: common.EventTypePut, Key: key, Value: cloneValue(stored)})
}

// deleteLocked removes key and publishes the change; an absent key has no
// change to report.
func (c *fakeCoordinator) deleteLocked(key string) {
	if _, ok := c.store[key]; !ok {
		return
	}
	delete(c.store, key)
	c.publishLocked(common.Event{Type: common.EventTypeDelete, Key: key})
}

// publishLocked queues ev on every matching watcher. It runs under c.mu and
// must never block, so it appends and signals rather than sending.
func (c *fakeCoordinator) publishLocked(ev common.Event) {
	for w := range c.watchers {
		if strings.HasPrefix(ev.Key, w.prefix) {
			w.enqueue(ev)
		}
	}
}

func (c *fakeCoordinator) removeWatcher(w *fakeWatcher) {
	c.mu.Lock()
	delete(c.watchers, w)
	c.mu.Unlock()
}

// cloneValue copies val, returning a non-nil zero-length slice for an empty
// input so a stored empty value never reads back as absence.
func cloneValue(val []byte) []byte {
	out := make([]byte, len(val))
	copy(out, val)
	return out
}

// fakeLease is a held lease. Its state is guarded by the coordinator's lock, so
// a renewal and an expiry racing each other resolve in the same single order
// that decides whether a contender may acquire the key.
type fakeLease struct {
	coord *fakeCoordinator
	key   string
	ttl   time.Duration
	done  chan struct{}

	timer    *time.Timer
	over     bool
	released bool
}

var _ common.Lease = (*fakeLease)(nil)

func (l *fakeLease) Key() string           { return l.key }
func (l *fakeLease) Done() <-chan struct{} { return l.done }

// Renew extends the lease. A renewal arriving after ownership has ended reports
// the loss rather than resurrecting the lease — a sibling goroutine fencing on
// Done must not be given a different answer.
func (l *fakeLease) Renew(ctx context.Context) error {
	l.coord.record("Renew")
	if err := ctx.Err(); err != nil {
		return err
	}
	l.coord.mu.Lock()
	hook := l.coord.renewHook
	l.coord.mu.Unlock()
	if hook != nil {
		hook(l.key)
	}

	// The state is read AFTER the hook, not before: the hook may be what ends
	// the lease, and a renewal must answer for the world it returns into.
	l.coord.mu.Lock()
	defer l.coord.mu.Unlock()
	if l.over {
		return fmt.Errorf("%w: %s", errFakeLeaseLost, l.key)
	}
	if l.coord.renewErr != nil {
		// An unacknowledged renewal does NOT extend the deadline.
		return l.coord.renewErr
	}
	l.timer.Reset(l.ttl)
	return nil
}

// Release relinquishes the lease. A refused release is NOT a release: the error
// is returned, Done stays open and the key stays bound.
func (l *fakeLease) Release(ctx context.Context) error {
	l.coord.record("Release")
	if err := ctx.Err(); err != nil {
		return err
	}
	l.coord.mu.Lock()
	if l.released {
		l.coord.mu.Unlock()
		return nil
	}
	if injected := l.coord.releaseErr; injected != nil {
		if l.coord.releaseErrRemaining > 0 {
			l.coord.releaseErrRemaining--
			if l.coord.releaseErrRemaining == 0 {
				l.coord.releaseErr = nil
			}
		}
		l.coord.mu.Unlock()
		return injected
	}
	l.released = true
	closing := !l.over
	if closing {
		l.over = true
		l.timer.Stop()
		l.releaseKeyLocked()
	}
	l.coord.mu.Unlock()

	if closing {
		close(l.done)
	}
	return nil
}

// expire ends the lease at its deadline. It is the one implementation of
// expiry: the TTL timer and the deterministic expireNow hook both land here.
func (l *fakeLease) expire() {
	l.coord.mu.Lock()
	if l.over {
		l.coord.mu.Unlock()
		return
	}
	l.over = true
	l.timer.Stop()
	l.releaseKeyLocked()
	l.coord.mu.Unlock()

	close(l.done)
}

// releaseKeyLocked unbinds the lease from its key, but only while this lease is
// still the registered holder, so a lease that lost the key some other way does
// not delete the next holder's on its way out.
func (l *fakeLease) releaseKeyLocked() {
	if l.coord.leases[l.key] != l {
		return
	}
	delete(l.coord.leases, l.key)
	l.coord.deleteLocked(l.key)
}

// fakeWatcher is one registered Watch. Events are queued under its own lock and
// delivered by pump, so the coordinator's lock is never held across a send.
type fakeWatcher struct {
	prefix string
	out    chan common.Event
	wake   chan struct{}

	mu      sync.Mutex
	pending []common.Event
	stopped bool
}

func (w *fakeWatcher) enqueue(ev common.Event) {
	w.mu.Lock()
	w.pending = append(w.pending, ev)
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// pump delivers queued events until ctx is done, then closes the channel — the
// close being the caller's only end-of-watch signal.
func (w *fakeWatcher) pump(ctx context.Context, c *fakeCoordinator) {
	defer close(w.out)
	defer c.removeWatcher(w)

	for {
		w.mu.Lock()
		batch := w.pending
		w.pending = nil
		stopped := w.stopped
		w.mu.Unlock()

		for _, ev := range batch {
			select {
			case w.out <- ev:
			case <-ctx.Done():
				return
			}
		}
		if stopped {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		}
	}
}
