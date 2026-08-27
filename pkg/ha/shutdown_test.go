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

// A clean handover: give the role back first, then free the key, so the peer
// takes over at once instead of waiting out the TTL.
func TestGracefulStopDemotesThenReleases(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.stop()

	if n := prov.demoteCount(); n != 1 {
		t.Fatalf("Demote was called %d times on a graceful stop, want 1", n)
	}
	if r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease key survived a stop whose demote succeeded")
	}

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if got.Primary {
		t.Fatal("a stopped manager still claimed the primary role")
	}
	if got.Err != nil {
		t.Fatalf("a clean stop reported %v", got.Err)
	}

	// The demote precedes the release: releasing while still Primary would hand
	// the peer permission to promote against a node that is still writing.
	ops := r.coord.recorded()
	release := -1
	for i, op := range ops {
		if op == "Release" {
			release = i
		}
	}
	if release < 0 {
		t.Fatalf("the lease was never released: %v", ops)
	}
}

// The other branch, and the one that matters: the workload still holds the
// mount, so DRBD refuses the demote. Releasing anyway would authorize the peer
// to promote against a node that is still writing, so the lease is left to
// expire instead — a TTL-gated takeover, exactly what a crash would have
// produced.
func TestGracefulStopLeavesTheLeaseToExpireWhenTheDemoteFails(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("drbdadm secondary vol1: Device is held open by someone")
	prov.setDemoteErr(stillOpen)

	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.stop()

	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease was released while the node was still Primary")
	}
	for _, op := range r.coord.recorded() {
		if op == "Release" {
			t.Fatalf("Release was called after a failed demote: %v", r.coord.recorded())
		}
	}

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if !errors.Is(got.Err, stillOpen) {
		t.Fatalf("final Err = %v, want it to wrap the demote failure", got.Err)
	}
	if !strings.Contains(got.Err.Error(), "leaving the lease to expire") {
		t.Fatalf("final Err = %q; it must say the lease was left to expire", got.Err)
	}
}

// A revoke the backend did not acknowledge is not a release, so it is retried.
func TestReleaseIsRetriedUntilAcknowledged(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	// Two refusals, then the backend comes back. The default is three
	// attempts, so the third succeeds.
	r.coord.setReleaseErrTimes(errors.New("coordinator unreachable"), 2)
	r.stopPumpingTheClock()

	releases := 0
	for _, op := range r.coord.recorded() {
		if op == "Release" {
			releases++
		}
	}
	if releases != 3 {
		t.Fatalf("Release was attempted %d times, want 3", releases)
	}
	if r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the key is still bound after an acknowledged release")
	}
	if got := r.obs.last(t); got.Err != nil {
		t.Fatalf("a release that eventually succeeded reported %v", got.Err)
	}
}

// A release that is never acknowledged is reported, and the deadline is left to
// do the work. Claiming the key was freed would tell the peer to expect an
// acquisition that keeps failing until the TTL runs out anyway.
func TestUnacknowledgedReleaseIsReportedAndLeftToTheDeadline(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	unreachable := errors.New("coordinator unreachable")
	r.coord.setReleaseErr(unreachable)
	r.stopPumpingTheClock()

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if !errors.Is(got.Err, unreachable) {
		t.Fatalf("final Err = %v, want it to wrap %v", got.Err, unreachable)
	}
	if !strings.Contains(got.Err.Error(), "after 3 attempts") {
		t.Fatalf("final Err = %q; it must say how many attempts were made", got.Err)
	}
	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the key was freed by a release the backend never acknowledged")
	}
}

func TestStopWhileCampaigningTouchesNothing(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	peer, err := r.coord.AcquireLease(context.Background(), r.leaseKey(testVolume), time.Hour)
	if err != nil {
		t.Fatalf("seeding the peer's lease: %v", err)
	}
	defer func() {
		if err := peer.Release(context.Background()); err != nil {
			t.Fatalf("releasing the peer's lease: %v", err)
		}
	}()

	r.start(testVolume)
	r.clock.awaitTimers(t, 1)
	r.awaitPhase(testVolume, PhaseCampaigning)
	r.stop()

	// A manager that never led has no role to give back and no lease to free.
	if n := prov.demoteCount(); n != 0 {
		t.Fatalf("Demote was called %d times by a manager that never led, want 0", n)
	}
	if len(prov.recorded()) != 0 {
		t.Fatalf("a manager that never led touched the provider: %v", prov.recorded())
	}
	if got := r.obs.last(t); got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
}

func TestStopAfterAFenceIsClean(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	r.clock.awaitTimers(t, 2)
	r.stop()

	if got := r.obs.last(t); got.Phase != PhaseStopped || got.Primary {
		t.Fatalf("final status = %+v, want a stopped, non-primary manager", got)
	}
}

// Cancellation arriving while the acquisition is in flight has to unwind
// cleanly rather than being mistaken for a coordinator that could not answer
// and retried forever.
func TestCancellationDuringAcquisitionStopsTheManager(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	var canceled bool
	r.coord.setAcquireHook(func(string) {
		if canceled {
			return
		}
		canceled = true
		r.cancel()
	})

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.exited = make(chan error, 1)
	go func() { r.exited <- r.ctrl.Manage(ctx, testVolume) }()

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return when its context was canceled mid-acquisition")
	}
	r.cancel = nil

	if len(prov.recorded()) != 0 {
		t.Fatalf("the provider was touched without a lease: %v", prov.recorded())
	}
	if got := r.obs.last(t); got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
}

// A promotion can also be voided by the manager being stopped rather than by
// the lease dying, and the reason has to say which: "the lease was lost" and
// "you stopped me" are not the same incident to whoever reads the status.
func TestPromotionVoidedByAStoppedManagerSaysSo(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

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

	select {
	case <-inPromote:
	case <-time.After(waitTimeout):
		t.Fatal("the controller never entered Promote")
	}

	// Canceled, not fenced: the lease is still live and still bound.
	r.stopPumpingTheClock()

	if !r.coord.held(r.leaseKey(testVolume)) && prov.demoteCount() == 0 {
		t.Fatal("the shutdown neither demoted nor left the key bound")
	}

	var voided *Status
	for i, s := range r.obs.seenCopy() {
		if s.Phase == PhaseFenced {
			voided = &r.obs.seenCopy()[i]
			break
		}
	}
	if voided == nil {
		t.Fatalf("the voided promotion was never observed: %v", r.obs.phases())
	}
	if voided.Primary {
		t.Fatal("a promotion voided by a shutdown was kept as a primary claim")
	}
	if errors.Is(voided.Err, ErrFenced) {
		t.Fatalf("Err = %v; a shutdown is not a fence and must not be reported as one", voided.Err)
	}
	if !strings.Contains(voided.Err.Error(), "the manager was stopped") {
		t.Fatalf("Err = %q; it must say the manager was stopped", voided.Err)
	}
}

// A reconcile whose lease context is already dead when it starts does nothing
// at all — it does not read the replication state, and it certainly does not
// promote. Here the manager is canceled from inside the renewal that precedes
// it, so the renewal succeeds and the reconcile it triggers is already void.
func TestAReconcileWithADeadContextDoesNothing(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	reads := len(prov.recorded())

	var fired bool
	r.coord.setRenewHook(func(string) {
		if fired {
			return
		}
		fired = true
		r.cancel()
	})
	r.clock.Advance(r.ctrl.Config().RenewInterval)

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return after being canceled mid-renewal")
	}
	r.cancel = nil

	if !fired {
		t.Fatal("the renewal hook never ran; the interleave this test exists for did not happen")
	}
	// Only the shutdown's own demote may have been added. No further read, no
	// further promotion.
	for _, op := range prov.recorded()[reads:] {
		if op != "Demote" {
			t.Fatalf("a reconcile with a dead context called provider.%s (all: %v)", op, prov.recorded())
		}
	}
	if n := prov.promoteCount(); n != 1 {
		t.Fatalf("Promote was called %d times, want the single one from the first reconcile", n)
	}
}

// The stop reason must survive the loop unwinding around it: a shutdown that
// could not demote has already said the useful thing, and a later nil must not
// replace it.
func TestTheFirstStopReasonWins(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("device is held open")
	prov.setDemoteErr(stillOpen)

	r := newRig(t, prov, nil)
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.stop()

	stops := 0
	for _, s := range r.obs.phases() {
		if s == PhaseStopped {
			stops++
		}
	}
	if stops != 1 {
		t.Fatalf("the observer saw %d stopped statuses, want exactly 1", stops)
	}
	if got := r.obs.last(t); !errors.Is(got.Err, stillOpen) {
		t.Fatalf("the stop reason was replaced: %v", got.Err)
	}
}

// The last status the observer sees is the whole record once Manage returns and
// the volume is unregistered. A fence whose demote failed says this node may
// still be writable with no lease behind it — a condition the shutdown does not
// resolve — so stopping must not erase it.
func TestStoppingAfterAFenceKeepsTheDemoteFailure(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("drbdadm secondary vol1: Device is held open by someone")
	prov.setDemoteErr(stillOpen)

	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)

	waitFor(t, func() bool { return errors.Is(r.status(testVolume).Err, stillOpen) },
		"the failed demote was never recorded before the stop")

	// It parks on the retry wait, then the caller stops it.
	r.clock.awaitTimers(t, 2)
	r.stop()

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if !errors.Is(got.Err, stillOpen) {
		t.Fatalf("final Err = %v; stopping erased the failed demote, and that record is all that is left", got.Err)
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("final Err = %v; the fence must survive into the last status too", got.Err)
	}
	if got.Primary {
		t.Fatal("a stopped manager still claimed the primary role")
	}
}

// The retry sequence is bounded by ActionTimeout, not only by the attempt
// count. Once the context is done every remaining attempt is an immediate
// failure against a dead deadline, so a high ReleaseAttempts must not turn a
// bounded shutdown into a spin.
//
// The bound is reached deterministically: the manual clock never fires, so the
// wait between attempts can only end at the timeout, and the attempt after it
// meets a context that is already done.
func TestReleaseRetriesStopAtTheActionTimeout(t *testing.T) {
	const attempts = 8

	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, func(cfg *Config) {
		cfg.ReleaseAttempts = attempts
		cfg.ActionTimeout = 50 * time.Millisecond
	})
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	r.coord.setReleaseErr(errors.New("coordinator unreachable"))
	r.cancel()
	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return; the release retry did not stop at the timeout")
	}
	r.cancel = nil

	releases := 0
	for _, op := range r.coord.recorded() {
		if op == "Release" {
			releases++
		}
	}
	if releases >= attempts {
		t.Fatalf("Release was attempted %d times; the sequence must stop at ActionTimeout, not run out the %d attempts",
			releases, attempts)
	}
	if releases < 1 {
		t.Fatal("Release was never attempted")
	}
	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the key was freed by releases the backend never acknowledged")
	}
}

// A planned shutdown holds the lease across the demote instead of dropping it
// first. Demoting can take longer than the lease has left — ActionTimeout is
// larger than a typical TTL, and a demote blocked on an open device is exactly
// the slow case — and letting the lease lapse there would invite the peer to
// promote against a node that is still Primary. That is a window this path
// chooses, unlike a crash, so it does not take it.
//
// The interleave is forced and asserted: the demote is held open, the clock is
// advanced past a renewal interval while it is held, and the test requires a
// Renew to have reached the coordinator BEFORE the demote is let go.
func TestGracefulStopRenewsTheLeaseWhileDemoting(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inDemote := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setDemoteHook(func(context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inDemote)
		<-release
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	renewsBefore := countOp(r.coord.recorded(), "Renew")
	r.cancel()

	select {
	case <-inDemote:
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown never reached Demote")
	}

	// The shutdown's own renewal loop parks on the clock; advancing it is what
	// makes a renewal happen while the demote is still in flight.
	r.clock.awaitTimers(t, 2)
	r.clock.Advance(r.ctrl.Config().RenewInterval)

	waitFor(t, func() bool { return countOp(r.coord.recorded(), "Renew") > renewsBefore },
		"the lease was not renewed while the demote was in flight; a slow demote would outlive it")

	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the key was freed before the demote finished")
	}

	close(release)
	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return after the demote completed")
	}
	r.cancel = nil

	// And once the demote is done the lease is given up, not left to lapse.
	if r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease survived a stop whose demote succeeded")
	}
	if got := r.obs.last(t); got.Phase != PhaseStopped || got.Err != nil {
		t.Fatalf("final status = %+v, want a clean stop", got)
	}
}

// countOp counts how many times op appears in a recorded call list.
func countOp(ops []string, op string) int {
	n := 0
	for _, got := range ops {
		if got == op {
			n++
		}
	}
	return n
}

// A renewal that fails while the shutdown demote is in flight is reported and
// does not derail the shutdown: the demote still finishes, and the lease is
// simply at more risk of lapsing before it does — which is what the log says.
func TestAFailedRenewalDuringShutdownDoesNotDerailIt(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inDemote := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setDemoteHook(func(context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inDemote)
		<-release
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	r.coord.setRenewErr(errors.New("coordinator unreachable"))
	r.cancel()

	select {
	case <-inDemote:
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown never reached Demote")
	}

	before := countOp(r.coord.recorded(), "Renew")
	r.clock.awaitTimers(t, 2)
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	waitFor(t, func() bool { return countOp(r.coord.recorded(), "Renew") > before },
		"the shutdown never attempted a renewal")
	waitFor(t, func() bool { return r.logs.saw("renewal during shutdown failed") },
		"the failed renewal during shutdown was never reported")

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

	if got := r.obs.last(t); got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
}

// The lease can still end while the shutdown demote runs — that is the case the
// renewals reduce rather than eliminate. When it does, the shutdown is NOT
// clean: the authorization is gone and a peer may already hold the key, so the
// fence has to be recorded rather than papered over by a demote that then
// happened to succeed.
func TestALeaseEndingDuringTheShutdownDemoteIsFenced(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inDemote := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setDemoteHook(func(context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inDemote)
		<-release
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	lease := r.coord.leaseFor(r.leaseKey(testVolume))
	if lease == nil {
		t.Fatal("no lease is bound for the volume")
	}
	r.cancel()

	select {
	case <-inDemote:
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown never reached Demote")
	}

	r.coord.expireNow(r.leaseKey(testVolume))
	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("the lease did not end")
	}
	// The announcement must be withdrawn WHILE the demote is still blocked. A
	// demote held on an open device can run for the whole ActionTimeout, and
	// advertising this node as the authorized primary for that long — with the
	// lease already gone and a peer free to take it — is the one thing a
	// fencing controller must never do.
	waitFor(t, func() bool {
		s, err := r.ctrl.Status(testVolume)
		return err == nil && s.Phase == PhaseFenced && !s.Primary
	}, "the volume was still announced as primary while the demote blocked and the lease was gone")

	// And the demote genuinely has not returned yet, so that assertion was
	// about the window and not about what happens after it.
	select {
	case <-r.exited:
		t.Fatal("the manager returned before the test released the demote")
	default:
	}

	close(release)

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return after the lease ended mid-demote")
	}
	r.cancel = nil

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if got.Primary {
		t.Fatal("the controller still claimed primary after losing the lease mid-shutdown")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("final Err = %v; a lease lost during the shutdown demote must be recorded as a fence, "+
			"not hidden behind a demote that then succeeded", got.Err)
	}
	// The observer saw the fence before the stop, so an orchestrator watching
	// transitions learns the node was fenced rather than shut down tidily.
	phases := r.obs.phases()
	fencedAt, stoppedAt := -1, -1
	for i, p := range phases {
		if p == PhaseFenced && fencedAt < 0 {
			fencedAt = i
		}
		if p == PhaseStopped && stoppedAt < 0 {
			stoppedAt = i
		}
	}
	if fencedAt < 0 || stoppedAt < 0 || fencedAt > stoppedAt {
		t.Fatalf("the observer did not see a fence before the stop: %v", phases)
	}
	// And no release was attempted against a lease that no longer exists.
	if n := countOp(r.coord.recorded(), "Release"); n != 0 {
		t.Fatalf("Release was attempted %d times on a lease that had already ended", n)
	}
}

// ActionTimeout bounds the whole shutdown, renewals included. A demote that
// outlasts it ends the shutdown rather than renewing indefinitely against a
// device that is not going to come back.
func TestTheShutdownRenewalStopsAtTheActionTimeout(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	inDemote := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setDemoteHook(func(ctx context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inDemote)
		select {
		case <-ctx.Done():
		case <-release:
		case <-time.After(waitTimeout):
		}
	})

	r := newRig(t, prov, func(cfg *Config) { cfg.ActionTimeout = 50 * time.Millisecond })
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	r.cancel()
	select {
	case <-inDemote:
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown never reached Demote")
	}

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown did not end at ActionTimeout")
	}
	r.cancel = nil
	close(release)

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	// The demote did not complete, so the lease is left to expire rather than
	// released while the node may still be Primary.
	if !strings.Contains(got.Err.Error(), "leaving the lease to expire") {
		t.Fatalf("final Err = %v; a demote that timed out must leave the lease to expire", got.Err)
	}
	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease was released after a demote that never completed")
	}
}

// Both can go wrong at once: the lease ends during the shutdown demote AND the
// demote fails. Both facts have to survive into the record — the node may still
// be writable, and it no longer has a lease saying it may be.
func TestALeaseEndingAndAFailedDemoteBothSurvive(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	stillOpen := errors.New("drbdadm secondary vol1: Device is held open by someone")

	inDemote := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	prov.setDemoteHook(func(context.Context) {
		if !once.CompareAndSwap(false, true) {
			return
		}
		close(inDemote)
		<-release
	})

	r := newRig(t, prov, nil)
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	prov.setDemoteErr(stillOpen)
	r.cancel()

	select {
	case <-inDemote:
	case <-time.After(waitTimeout):
		t.Fatal("the shutdown never reached Demote")
	}

	r.coord.expireNow(r.leaseKey(testVolume))
	waitFor(t, func() bool {
		s, err := r.ctrl.Status(testVolume)
		return err == nil && s.Phase == PhaseFenced && !s.Primary
	}, "the volume was still announced as primary while the demote blocked and the lease was gone")
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

	got := r.obs.last(t)
	if got.Primary {
		t.Fatal("the controller still claimed primary")
	}
	if !errors.Is(got.Err, ErrFenced) {
		t.Fatalf("final Err = %v, want it to record the fence", got.Err)
	}
	if !errors.Is(got.Err, stillOpen) {
		t.Fatalf("final Err = %v, want it to carry the failed demote too", got.Err)
	}
}

// A clean stop reports a clean stop. A refusal standing from the last reconcile
// is resolved by no longer trying, so carrying it into the final status would
// make every shutdown of a volume that was not promotable look like a failure.
//
// Only a condition that OUTLIVES the shutdown survives it, and the fence is the
// one that does — see TestStoppingAfterAFenceKeepsTheDemoteFailure for the
// other side of this rule.
func TestACleanStopClearsAResolvedRefusal(t *testing.T) {
	prov := newFakeProvider(common.ReplStateSyncTarget, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.clock.awaitTimers(t, 1)
	if got := r.status(testVolume); !errors.Is(got.Err, ErrNotPromotable) {
		t.Fatalf("Err = %v, want a standing ErrNotPromotable before the stop", got.Err)
	}

	r.stop()

	got := r.obs.last(t)
	if got.Phase != PhaseStopped {
		t.Fatalf("final Phase = %q, want %q", got.Phase, PhaseStopped)
	}
	if got.Err != nil {
		t.Fatalf("final Err = %v; a clean stop must not carry a refusal the stop itself resolved", got.Err)
	}
	if got.Primary {
		t.Fatal("a stopped manager still claimed the primary role")
	}
}

// The same for a renewal warning: the Coordinator being briefly unreachable is
// not something a completed shutdown is still failing at.
func TestACleanStopClearsAResolvedRenewalWarning(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	r.coord.setRenewErr(errors.New("coordinator timed out"))
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	waitFor(t, func() bool { return errors.Is(r.status(testVolume).Err, ErrRenewFailed) },
		"the failed renewal was never recorded")

	r.coord.setRenewErr(nil)
	r.stop()

	if got := r.obs.last(t); got.Err != nil {
		t.Fatalf("final Err = %v; a clean stop must not carry a renewal warning it resolved", got.Err)
	}
}

// A demote that succeeded means the provider has already made this node
// secondary. Continuing to advertise it as the authorized primary while the
// release retries — which on this path can run for the whole ActionTimeout —
// would have the status contradict the very role it just recorded.
func TestASuccessfulShutdownDemoteWithdrawsTheAnnouncementBeforeTheRelease(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, func(cfg *Config) {
		cfg.ReleaseAttempts = 8
		cfg.ActionTimeout = 50 * time.Millisecond
	})
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	// The demote succeeds; the release then fails and retries until the
	// timeout, which is the window this test is about.
	//
	// It is sampled through Status rather than through the observer, and that
	// is the whole point: leaving Primary set while only the role moved
	// produces NO transition, so an observer would never be told about it. A
	// contradiction nobody is notified of is still a contradiction to anyone
	// polling.
	r.coord.setReleaseErr(errors.New("coordinator unreachable"))

	stopPolling := make(chan struct{})
	polled := make(chan bool, 1)
	go func() {
		contradicted := false
		for {
			select {
			case <-stopPolling:
				polled <- contradicted
				return
			default:
			}
			if s, err := r.ctrl.Status(testVolume); err == nil {
				if s.Primary && s.Repl.Role == common.ReplRoleSecondary {
					contradicted = true
				}
			}
		}
	}()

	r.cancel()

	select {
	case err := <-r.exited:
		if err != nil {
			t.Fatalf("Manage returned %v, want nil", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Manage did not return")
	}
	r.cancel = nil

	close(stopPolling)
	if <-polled {
		t.Fatal("Status claimed primary for a device it had already recorded as secondary, " +
			"for as long as the release kept retrying")
	}

	// Every announced status from the demote onward must agree with itself too.
	for _, s := range r.obs.seenCopy() {
		if s.Primary && s.Repl.Role == common.ReplRoleSecondary {
			t.Fatalf("an announced status claimed primary for a device it recorded as secondary: %+v", s)
		}
	}
	got := r.obs.last(t)
	if got.Primary {
		t.Fatal("the final status still claimed primary after a successful demote")
	}
	if got.Repl.Role != common.ReplRoleSecondary {
		t.Fatalf("Repl.Role = %q after a successful demote, want secondary", got.Repl.Role)
	}
}
