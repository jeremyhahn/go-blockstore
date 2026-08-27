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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// One goroutine per volume is the serialization the controller's check-then-act
// sequences rest on, so the admission has to hold under a real race and not
// merely under sequential calls.
//
// The barrier releases every caller at once; the assertion that matters is not
// the error count but the promotion count, because two admitted managers would
// each drive the provider.
func TestConcurrentManageAdmitsExactlyOne(t *testing.T) {
	const contenders = 8

	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gate sync.WaitGroup
	gate.Add(1)

	var (
		admitted atomic.Int32
		refused  atomic.Int32
		other    atomic.Int32
		running  sync.WaitGroup
	)
	running.Add(contenders)

	for i := 0; i < contenders; i++ {
		go func() {
			defer running.Done()
			gate.Wait()
			switch err := r.ctrl.Manage(ctx, testVolume); {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, ErrAlreadyManaged):
				refused.Add(1)
			default:
				other.Add(1)
			}
		}()
	}

	gate.Done()

	// The one admitted manager leads; the rest have already been refused.
	r.awaitPrimary(testVolume, true)
	waitFor(t, func() bool { return refused.Load() == contenders-1 },
		"only %d of %d contenders were refused", refused.Load(), contenders-1)

	if got := len(r.ctrl.Managed()); got != 1 {
		t.Fatalf("Managed() holds %d entries while %d callers raced, want 1", got, contenders)
	}
	if n := prov.promoteCount(); n != 1 {
		t.Fatalf("Promote was called %d times; a second admitted manager would have driven the provider too", n)
	}

	cancel()
	running.Wait()

	if got := admitted.Load(); got != 1 {
		t.Fatalf("%d managers were admitted, want exactly 1", got)
	}
	if got := other.Load(); got != 0 {
		t.Fatalf("%d callers failed with an unexpected error", got)
	}
}

// Status is read by anything that wants to know whether this node is primary,
// concurrently with the manager rewriting that state. This drives both sides
// hard under the race detector while the volume is actually transitioning.
func TestStatusIsSafeWhileTheControllerTransitions(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Both surfaces, and the error branch, since the volume is
				// unregistered the moment Manage returns.
				if s, err := r.ctrl.Status(testVolume); err == nil {
					_ = s.Primary
				}
				_ = r.ctrl.Managed()
			}
		}()
	}

	// Fence and re-elect a few times underneath the readers.
	//
	// Each cycle registers TWO timers — the renewal wait a leader parks on, and
	// the retry wait a fenced manager parks on — so the barriers step by two.
	// Advancing before the manager has parked would fire into a clock nobody is
	// waiting on and strand the loop.
	for i := 0; i < 3; i++ {
		r.clock.awaitTimers(t, 2*i+1)
		r.coord.expireNow(r.leaseKey(testVolume))
		r.awaitPhase(testVolume, PhaseFenced)
		r.clock.awaitTimers(t, 2*i+2)
		r.clock.Advance(r.ctrl.Config().RetryInterval)
		r.awaitPrimary(testVolume, true)
	}

	close(stop)
	readers.Wait()
}

// The contract's sharpest clause: a renewal that resolves after Done has closed
// reports the loss and never nil success. The controller must not turn such a
// renewal into a reconcile — the interleave is forced here by ending the lease
// from inside the renewal itself.
func TestARenewalResolvingAfterDoneClosedNeverPromotes(t *testing.T) {
	// Starting Inconsistent means the first reconcile refuses, so any promotion
	// this test sees can only have come from the renewal path.
	prov := newFakeProvider(common.ReplStateInconsistent, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("the first reconcile promoted an inconsistent volume %d time(s)", n)
	}

	// The volume becomes promotable, and the lease dies inside the very
	// renewal that would have led to promoting it.
	prov.setRepl(common.ReplStateUpToDate, common.ReplRoleSecondary)

	var fired atomic.Bool
	r.coord.setRenewHook(func(key string) {
		if fired.CompareAndSwap(false, true) {
			r.coord.expireNow(key)
		}
	})

	r.clock.Advance(r.ctrl.Config().RenewInterval)

	got := r.awaitPhase(testVolume, PhaseFenced)
	if !fired.Load() {
		t.Fatal("the renewal hook never ran; the interleave this test exists for did not happen")
	}
	if got.Primary {
		t.Fatal("the controller claimed primary from a renewal that had already lost the lease")
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("a renewal resolving after Done closed led to %d promotion(s), want 0", n)
	}
}

// Cancellation landing between the state read and the promotion. The read
// completes honestly — that ordering is real — and the guard before Promote is
// what stops the controller acting on an answer its lease no longer covers.
func TestCancellationBetweenTheStateReadAndThePromotion(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inRead := make(chan struct{})
	var once atomic.Bool
	prov.setReplHook(func(ctx context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inRead)
		select {
		case <-ctx.Done():
		case <-time.After(waitTimeout):
		}
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	select {
	case <-inRead:
	case <-time.After(waitTimeout):
		t.Fatal("the controller never entered ReplicationState")
	}
	r.coord.expireNow(r.leaseKey(testVolume))

	got := r.awaitPhase(testVolume, PhaseFenced)
	if got.Primary {
		t.Fatal("the controller promoted on a read its lease no longer covered")
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times after the lease died mid-read, want 0", n)
	}
}
