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
	"sync"
	"testing"
	"time"
)

// waitTimeout bounds every barrier in this package's tests. A barrier that is
// not reached is a hung controller, and a hung controller must fail the test
// with a message rather than the suite's timeout.
const waitTimeout = 5 * time.Second

// pollInterval is how often a barrier re-checks. Short enough that a test
// finishes promptly, long enough not to spin a core.
const pollInterval = 200 * time.Microsecond

// testClock is a manually driven [Clock].
//
// Nothing fires unless a test advances it. That is what makes the controller's
// loop observable: it parks in its select waiting on After, the test can then
// establish whatever state it wants to interleave, and only then does the
// renewal tick happen. Wall-clock sleeps would make the same tests both slower
// and less certain about what they proved.
type testClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*clockWaiter

	// created counts every waiter ever registered. Barriers are written
	// against it rather than against the pending count, because pending is not
	// monotone: a loop that exits through a different branch of its select
	// leaves its timer behind, so "one waiter is pending" can mean an orphan
	// rather than the loop being parked where the test expects.
	created int
}

type clockWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

// newTestClock returns a clock at a fixed, arbitrary instant.
func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After registers a waiter. The channel is buffered so firing it never blocks
// the advancing goroutine, matching time.After.
func (c *testClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &clockWaiter{deadline: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.waiters = append(c.waiters, w)
	c.created++
	return w.ch
}

// Advance moves the clock and fires every waiter now due.
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due, keep []*clockWaiter
	for _, w := range c.waiters {
		if !w.deadline.After(now) {
			due = append(due, w)
		} else {
			keep = append(keep, w)
		}
	}
	c.waiters = keep
	c.mu.Unlock()

	for _, w := range due {
		w.ch <- now
	}
}

// registered returns the monotone count of waiters ever created.
func (c *testClock) registered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.created
}

// awaitTimers blocks until at least n timers have been registered in total.
//
// It is the barrier that says "the controller has finished the work leading up
// to its nth wait and is parked". Advancing before that point would fire into a
// clock nobody is waiting on and the tick would be lost, which is the failure
// mode that makes a timing test flaky instead of failing.
func (c *testClock) awaitTimers(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for c.registered() < n {
		if time.Now().After(deadline) {
			t.Fatalf("the controller registered only %d timer(s); the test waited for %d", c.registered(), n)
		}
		time.Sleep(pollInterval)
	}
}

// waitFor polls cond until it holds, failing the test with the given message if
// it does not within waitTimeout.
func waitFor(t *testing.T, cond func() bool, format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(format, args...)
		}
		time.Sleep(pollInterval)
	}
}
