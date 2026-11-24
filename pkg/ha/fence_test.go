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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestLeaseLossFencesAndYieldsTheRole(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	before := prov.demoteCount()
	r.coord.expireNow(r.leaseKey(testVolume))

	got := r.awaitPhase(testVolume, PhaseFenced)
	if got.Primary {
		t.Fatal("a fenced controller still claimed the primary role")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("Err = %v, want ErrFenced", got.Err)
	}

	// The role is given back on a fresh context, because the lease context is
	// exactly what just ended.
	waitFor(t, func() bool { return prov.demoteCount() > before },
		"the fenced controller never attempted a demote")

	// Exactly one demote for one fencing event: the void path deliberately
	// leaves the demote to this one.
	if n := prov.demoteCount(); n != before+1 {
		t.Fatalf("demote was called %d times for one fence, want 1", n-before)
	}
}

// Fenced means fenced. A controller that has lost the lease must initiate no
// promotion at all, even when the volume looks perfectly promotable and the
// cadence keeps ticking.
func TestFencedControllerInitiatesNoPromotion(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	// Hold the key so re-election cannot quietly restore the primary claim and
	// make this test pass for the wrong reason.
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)

	// A peer takes the freed key, so this controller stays a contender.
	peer, err := r.coord.AcquireLease(context.Background(), r.leaseKey(testVolume), time.Hour)
	if err != nil {
		t.Fatalf("the peer could not take the freed key: %v", err)
	}
	defer func() {
		if err := peer.Release(context.Background()); err != nil {
			t.Fatalf("releasing the peer's lease: %v", err)
		}
	}()

	after := prov.promoteCount()
	// Two timers exist now, plus one per round; the barrier comes before the advance.
	for i := 0; i < 5; i++ {
		r.clock.awaitTimers(t, 2+i)
		r.clock.Advance(r.ctrl.Config().RetryInterval)
	}
	r.clock.awaitTimers(t, 7)
	if n := prov.promoteCount(); n != after {
		t.Fatalf("a fenced contender initiated %d further promotion(s)", n-after)
	}
	if s := r.status(testVolume); s.Primary {
		t.Fatal("a fenced contender reported itself primary")
	}
}

// The lease dies while Promote is in flight; the hook records what the call saw.
func TestFenceCancelsAPromotionAlreadyInFlight(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inPromote := make(chan struct{})
	var sawCancellation atomic.Bool
	prov.setPromoteHook(func(ctx context.Context) {
		close(inPromote)
		// Wait for the fence to reach this call. Waiting on ctx.Done rather
		// than on a plain signal is what makes the assertion meaningful: if
		// the controller did not thread a cancellable context into Promote,
		// this times out and the test fails.
		select {
		case <-ctx.Done():
			sawCancellation.Store(true)
		case <-time.After(waitTimeout):
		}
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	select {
	case <-inPromote:
	case <-time.After(waitTimeout):
		t.Fatal("the controller never entered Promote")
	}

	// The lease dies mid-promotion.
	if !r.coord.expireNow(r.leaseKey(testVolume)) {
		t.Fatal("expireNow found no lease to expire")
	}

	got := r.awaitPhase(testVolume, PhaseFenced)
	if !sawCancellation.Load() {
		t.Fatal("the in-flight promotion was never canceled; the fence did not reach work already running")
	}
	if r.obs.everPrimary() {
		t.Fatal("the controller announced primary from a promotion its lease did not cover")
	}
	if got.Primary {
		t.Fatal("the controller claimed primary from a promotion its lease did not cover")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("Err = %v, want ErrFenced", got.Err)
	}
	if !strings.Contains(got.Err.Error(), "void") {
		t.Fatalf("Err = %q; a promotion cut short by a fence is reported as void", got.Err)
	}
}

// Promote succeeded after the lease was gone; the controller must drop the claim.
func TestPromotionThatSucceedsAfterLeaseLossIsVoided(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	prov.setPromoteCompletesAfterCancel()

	inPromote := make(chan struct{})
	prov.setPromoteHook(func(ctx context.Context) {
		close(inPromote)
		select {
		case <-ctx.Done():
		case <-time.After(waitTimeout):
		}
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	select {
	case <-inPromote:
	case <-time.After(waitTimeout):
		t.Fatal("the controller never entered Promote")
	}
	r.coord.expireNow(r.leaseKey(testVolume))

	got := r.awaitPhase(testVolume, PhaseFenced)
	if r.obs.everPrimary() {
		t.Fatal("a promotion that landed after the lease died was announced as a primary claim; " +
			"an orchestrator would have mounted on it")
	}
	if got.Primary {
		t.Fatal("a promotion that landed after the lease died was kept as a primary claim")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("Err = %v, want ErrFenced", got.Err)
	}

	// And the role is handed back, narrowing the window in which this node is
	// writable with no lease behind it.
	waitFor(t, func() bool { return prov.demoteCount() > 0 },
		"a voided promotion was never followed by a demote")
}

// DRBD refuses to demote an open device. A fenced controller whose demote
// failed must not read like one that succeeded: the difference is whether the
// node is still writable, which is the whole question.
func TestDemoteFailureAfterAFenceIsReported(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("drbdadm secondary vol1: Device is held open by someone")
	prov.setDemoteErr(stillOpen)

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)

	var got Status
	waitFor(t, func() bool {
		got = r.status(testVolume)
		return errors.Is(got.Err, stillOpen)
	}, "the failed demote was never reported (status: %+v)", &got)

	if got.Primary {
		t.Fatal("a fenced controller kept its primary claim because the demote failed")
	}
	// Both facts survive: the fence, and the fact that the node may still be
	// writable.
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("Err = %v; the fence must survive alongside the demote failure", got.Err)
	}
}

func TestFencedControllerCampaignsAgainAndReElects(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	first := r.awaitPrimary(testVolume, true)
	if first.Epoch != 1 {
		t.Fatalf("first Epoch = %d, want 1", first.Epoch)
	}
	r.clock.awaitTimers(t, 1)

	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)

	// The retry after a fence is what re-elects. The key is free — this fake
	// reaps it, which is the contract go-qrdb #174 does not yet honor when
	// embedded.
	r.clock.awaitTimers(t, 2)
	r.clock.Advance(r.ctrl.Config().RetryInterval)

	second := r.awaitPrimary(testVolume, true)
	if second.Phase != PhaseLeading {
		t.Fatalf("Phase = %q after re-election, want %q", second.Phase, PhaseLeading)
	}
	if second.Epoch != 2 {
		t.Fatalf("Epoch = %d after re-election, want 2; a promotion belongs to the epoch it was issued under", second.Epoch)
	}
	if second.Err != nil {
		t.Fatalf("a re-elected leader still carries %v", second.Err)
	}
}

// A read that failed because the lease died is not reported as a provider failure.
func TestAStateReadCutShortByAFenceIsNotAProviderFailure(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	killed := errors.New("drbdsetup status: signal: killed")
	prov.setReplErr(killed)

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
		t.Fatal("the controller claimed primary after a read it could not complete")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("Err = %v, want ErrFenced", got.Err)
	}
	if errors.Is(got.Err, killed) {
		t.Fatalf("Err = %v; a read killed by the fence must not be reported as a provider failure", got.Err)
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times after the read was canceled, want 0", n)
	}
}

// A lease ending as the manager is canceled is recorded as a fence; the tie is forced inside ReplicationState.
func TestAFenceRacingAShutdownIsStillRecordedAsAFence(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inRead := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setReplHook(func(context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inRead)
		<-release
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)

	select {
	case <-inRead:
	case <-time.After(waitTimeout):
		t.Fatal("the controller never entered ReplicationState")
	}

	lease := r.coord.leaseFor(r.leaseKey(testVolume))
	if lease == nil {
		t.Fatal("no lease is bound for the volume")
	}
	r.coord.expireNow(r.leaseKey(testVolume))
	r.cancel()

	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("the lease did not end")
	}
	// r.cancel returns only once the context is canceled, so by this line both
	// conditions the loop will meet are already established.
	close(release)

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return")
	}
	r.cancel = nil

	phases := r.obs.phases()
	var fenced bool
	for _, p := range phases {
		if p == PhaseFenced {
			fenced = true
		}
	}
	if !fenced {
		t.Fatalf("a lease that ended alongside the shutdown was never recorded as a fence: %v", phases)
	}
	if r.obs.everPrimary() {
		t.Fatal("the controller announced primary on a read its lease no longer covered")
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times after the lease died mid-read, want 0", n)
	}
}

// A fence whose demote failed leaves the node possibly writable with no lease
// behind it. That condition is not resolved by the controller getting on with
// its retry loop, so a contender's error must not replace it in the status —
// which is exactly when nobody would be watching.
func TestAnUnyieldedRoleSurvivesTheRetryLoop(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("drbdadm secondary vol1: Device is held open by someone")
	prov.setDemoteErr(stillOpen)

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	waitFor(t, func() bool { return errors.Is(r.status(testVolume).Err, ErrRoleNotYielded) },
		"the failed demote was never recorded")

	// A peer takes the freed key so this controller stays a contender.
	peer, err := r.coord.AcquireLease(context.Background(), r.leaseKey(testVolume), time.Hour)
	if err != nil {
		t.Fatalf("the peer could not take the freed key: %v", err)
	}
	defer func() {
		if err := peer.Release(context.Background()); err != nil {
			t.Fatalf("releasing the peer's lease: %v", err)
		}
	}()

	r.clock.awaitTimers(t, 2)
	r.clock.Advance(r.ctrl.Config().RetryInterval)
	r.awaitPhase(testVolume, PhaseCampaigning)

	got := r.status(testVolume)
	if !errors.Is(got.Err, ErrRoleNotYielded) {
		t.Fatalf("Err = %v; campaigning erased the fact that this node may still be writable", got.Err)
	}
	if !errors.Is(got.Err, stillOpen) {
		t.Fatalf("Err = %v, want it to still carry the demote failure", got.Err)
	}
	if got.Primary {
		t.Fatal("a contender claimed primary")
	}
}

// A fence whose demote succeeded carries no hazard.
func TestACleanlyYieldedRoleDoesNotMaskTheCampaignError(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	waitFor(t, func() bool { return prov.demoteCount() > 0 }, "the fence never demoted")

	peer, err := r.coord.AcquireLease(context.Background(), r.leaseKey(testVolume), time.Hour)
	if err != nil {
		t.Fatalf("the peer could not take the freed key: %v", err)
	}
	defer func() {
		if err := peer.Release(context.Background()); err != nil {
			t.Fatalf("releasing the peer's lease: %v", err)
		}
	}()

	r.clock.awaitTimers(t, 2)
	r.clock.Advance(r.ctrl.Config().RetryInterval)

	waitFor(t, func() bool { return errors.Is(r.status(testVolume).Err, common.ErrLeaseHeld) },
		"the contender's own error never surfaced (status: %+v)", r.status(testVolume))
}

// Status.Repl.Role is documented as the device's actual role, so a demote that
// succeeded has to move it. Reporting primary for a node this controller has
// just demoted is the one direction of that lie that matters.
func TestASuccessfulDemoteUpdatesTheReportedRole(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	got := r.awaitPrimary(testVolume, true)
	if got.Repl.Role != common.ReplRolePrimary {
		t.Fatalf("Repl.Role = %q after promotion, want primary", got.Repl.Role)
	}
	r.clock.awaitTimers(t, 1)

	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	waitFor(t, func() bool { return prov.demoteCount() > 0 }, "the fence never demoted")

	waitFor(t, func() bool { return r.status(testVolume).Repl.Role == common.ReplRoleSecondary },
		"Repl.Role still reports primary for a device the controller demoted (status: %+v)",
		r.status(testVolume))
}

// A failed demote leaves the recorded role alone.
func TestAFailedDemoteLeavesTheReportedRoleAlone(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	prov.setDemoteErr(errors.New("drbdadm secondary vol1: Device is held open by someone"))

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	waitFor(t, func() bool { return errors.Is(r.status(testVolume).Err, ErrRoleNotYielded) },
		"the failed demote was never recorded")

	if got := r.status(testVolume).Repl.Role; got != common.ReplRolePrimary {
		t.Fatalf("Repl.Role = %q; a failed demote must not claim the role was given back", got)
	}
}

// The lease's Done has closed while leaseCtx is still live; reconcile is called directly in that state.
func TestReconcileRefusesOnAClosedDoneWithALiveContext(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	v, err := r.ctrl.register(testVolume)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	lease, err := r.coord.AcquireLease(context.Background(), v.key, DefaultLeaseTTL)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	v.leading(r.clock.Now().Add(DefaultLeaseTTL), lease.Key())

	// The lease ends. No watcher exists here at all, which is the strongest
	// form of "the watcher has not run yet".
	if !r.coord.expireNow(v.key) {
		t.Fatal("expireNow found no lease")
	}
	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("Done did not close")
	}

	ctx := context.Background()
	if ctx.Err() != nil {
		t.Fatal("the context must be live for this test to mean anything")
	}
	r.ctrl.reconcile(ctx, v, lease)

	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times with the lease already over, want 0", n)
	}
	if got := v.snapshot(); got.Primary {
		t.Fatal("the controller announced primary for a volume whose lease had ended")
	}
	if r.obs.everPrimary() {
		t.Fatal("the observer was told this node was primary after the lease ended")
	}
	if len(prov.recorded()) != 0 {
		t.Fatalf("the provider was touched at all with no authority: %v", prov.recorded())
	}
}
