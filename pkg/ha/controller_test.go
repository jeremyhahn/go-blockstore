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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestManageRejectsAVolumeIDThatCannotBecomeAKey(t *testing.T) {
	tests := []struct {
		name     string
		volID    string
		contains string
	}{
		{"empty", "", "is empty"},
		{"a separator would escape the key prefix", "tenant/vol1", "outside the configured prefix"},
		{"a newline would corrupt every line the key appears in", "vol\n1", "control character"},
		{"a NUL likewise", "vol\x00", "control character"},
		{"and DEL", "vol\x7f", "control character"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary), nil)
			err := r.ctrl.Manage(context.Background(), tt.volID)
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("Manage(%q): got %v, want common.ErrInvalidArgument", tt.volID, err)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("Manage(%q): %q does not mention %q", tt.volID, err, tt.contains)
			}
			if got := r.coord.recorded(); len(got) != 0 {
				t.Fatalf("a rejected volume id still reached the coordinator: %v", got)
			}
		})
	}
}

func TestManageRefusesASecondManagerForTheSameVolume(t *testing.T) {
	r := newRig(t, newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary), nil)
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)

	// One goroutine per volume is what serializes the controller's
	// check-then-act sequences, so a second manager is refused rather than
	// allowed to interleave with the first.
	err := r.ctrl.Manage(context.Background(), testVolume)
	if !errors.Is(err, ErrAlreadyManaged) {
		t.Fatalf("second Manage: got %v, want ErrAlreadyManaged", err)
	}

	if got := r.ctrl.Managed(); !reflect.DeepEqual(got, []string{testVolume}) {
		t.Fatalf("Managed() = %v, want [%q]", got, testVolume)
	}
}

func TestStatusReportsUnmanagedVolumes(t *testing.T) {
	r := newRig(t, newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary), nil)

	if _, err := r.ctrl.Status("nobody"); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Status of an unmanaged volume: got %v, want ErrNotManaged", err)
	}
	if got := r.ctrl.Managed(); len(got) != 0 {
		t.Fatalf("Managed() = %v on a fresh controller, want empty", got)
	}

	// The claim is released when Manage returns, so the volume can be managed
	// again — by this controller or by a replacement process.
	r.start(testVolume)
	r.awaitPrimary(testVolume, true)
	r.stop()

	waitFor(t, func() bool {
		_, err := r.ctrl.Status(testVolume)
		return errors.Is(err, ErrNotManaged)
	}, "the volume was still managed after Manage returned")
}

func TestLeaderPromotesAnUpToDateVolume(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	got := r.awaitPrimary(testVolume, true)

	if got.Phase != PhaseLeading {
		t.Fatalf("Phase = %q, want %q", got.Phase, PhaseLeading)
	}
	if got.Epoch != 1 {
		t.Fatalf("Epoch = %d, want 1 for a first acquisition", got.Epoch)
	}
	if got.LeaseKey != r.leaseKey(testVolume) {
		t.Fatalf("LeaseKey = %q, want %q", got.LeaseKey, r.leaseKey(testVolume))
	}
	if got.NodeID != testNode {
		t.Fatalf("NodeID = %q, want %q", got.NodeID, testNode)
	}
	if got.Err != nil {
		t.Fatalf("a healthy leader reported %v", got.Err)
	}
	if got.Repl.Conn != common.ReplStateUpToDate {
		t.Fatalf("Repl.Conn = %q, want %q", got.Repl.Conn, common.ReplStateUpToDate)
	}
	if want := r.clock.Now().Add(DefaultLeaseTTL); !got.LeaseDeadline.Equal(want) {
		t.Fatalf("LeaseDeadline = %s, want %s", got.LeaseDeadline, want)
	}
	if n := prov.promoteCount(); n != 1 {
		t.Fatalf("Promote was called %d times, want 1", n)
	}
	if !r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease key is not bound while the controller leads")
	}
}

func TestLeaderRefusesToPromoteAnIneligibleVolume(t *testing.T) {
	for _, conn := range []common.ReplConnState{
		common.ReplStateSyncSource,
		common.ReplStateSyncTarget,
		common.ReplStateInconsistent,
		common.ReplStateStandalone,
		common.ReplStateConnecting,
		common.ReplStateDown,
		common.ReplStateUnknown,
	} {
		t.Run(string(conn), func(t *testing.T) {
			prov := newFakeProvider(conn, common.ReplRoleSecondary)
			r := newRig(t, prov, nil)
			r.start(testVolume)
			defer r.stop()

			// The barrier: the manager has completed its first reconcile and
			// parked on the renewal timer, so the refusal has definitely
			// happened rather than merely not happened yet.
			r.clock.awaitTimers(t, 1)

			got := r.status(testVolume)
			if got.Phase != PhaseLeading {
				t.Fatalf("Phase = %q; a refusal keeps the lease", got.Phase)
			}
			if got.Primary {
				t.Fatal("the controller claimed primary on a volume it refused to promote")
			}
			if !errors.Is(got.Err, ErrNotPromotable) {
				t.Fatalf("Err = %v, want ErrNotPromotable", got.Err)
			}
			if !strings.Contains(got.Err.Error(), string(conn)) {
				t.Fatalf("the refusal %q does not name the state %q", got.Err, conn)
			}
			if n := prov.promoteCount(); n != 0 {
				t.Fatalf("Promote was called %d times for a %q volume; it must be called 0 times", n, conn)
			}
		})
	}
}

func TestLeaderDoesNotRePromoteAVolumeAlreadyPrimary(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRolePrimary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	got := r.awaitPrimary(testVolume, true)
	if got.Phase != PhaseLeading {
		t.Fatalf("Phase = %q, want %q", got.Phase, PhaseLeading)
	}
	// ReplicationState already answered the question, and it does not mutate.
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times on a volume already Primary, want 0", n)
	}
}

func TestContenderRefusedByAHeldLeasePromotesNothing(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	// Another node already holds the key.
	peer, err := r.coord.AcquireLease(context.Background(), r.leaseKey(testVolume), time.Hour)
	if err != nil {
		t.Fatalf("seeding the peer's lease: %v", err)
	}

	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Phase != PhaseCampaigning {
		t.Fatalf("Phase = %q, want %q", got.Phase, PhaseCampaigning)
	}
	if got.Primary {
		t.Fatal("a contender claimed primary")
	}
	if !errors.Is(got.Err, common.ErrLeaseHeld) {
		t.Fatalf("Err = %v, want errors.Is common.ErrLeaseHeld", got.Err)
	}
	if got.Epoch != 0 {
		t.Fatalf("Epoch = %d; a contender that never acquired has no epoch", got.Epoch)
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times by a contender, want 0", n)
	}

	// It takes over once the holder's key is freed, on the next retry.
	if err := peer.Release(context.Background()); err != nil {
		t.Fatalf("releasing the peer's lease: %v", err)
	}
	r.clock.Advance(r.ctrl.Config().RetryInterval)
	r.awaitPrimary(testVolume, true)
}

// A Coordinator that cannot answer is not permission to write. The controller
// must land in exactly the same place as a lost election — promoting nothing —
// rather than treating an unreachable arbiter as an absent one.
func TestCoordinatorUnavailableFailsStopped(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	unreachable := errors.New("coordinator unreachable")
	r.coord.setAcquireErr(unreachable)

	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Phase != PhaseCampaigning {
		t.Fatalf("Phase = %q, want %q", got.Phase, PhaseCampaigning)
	}
	if got.Primary {
		t.Fatal("the controller claimed primary with no answer from the coordinator")
	}
	if !errors.Is(got.Err, unreachable) {
		t.Fatalf("Err = %v, want it to wrap %v", got.Err, unreachable)
	}
	if errors.Is(got.Err, common.ErrLeaseHeld) {
		t.Fatal("an operational failure must not be reported as a contended key")
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times with no lease, want 0", n)
	}
	if len(prov.recorded()) != 0 {
		t.Fatalf("the provider was touched at all without a lease: %v", prov.recorded())
	}

	// It recovers when the coordinator does.
	r.coord.setAcquireErr(nil)
	r.clock.Advance(r.ctrl.Config().RetryInterval)
	r.awaitPrimary(testVolume, true)
}

func TestReplicationStateFailurePreventsPromotion(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	boom := errors.New("drbdsetup: no such module")
	prov.setReplErr(boom)

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Primary {
		t.Fatal("the controller claimed primary without knowing the replication state")
	}
	if !errors.Is(got.Err, boom) {
		t.Fatalf("Err = %v, want it to wrap %v", got.Err, boom)
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times on an unreadable volume, want 0", n)
	}
}

// DRBD refuses a promotion precisely when promoting would be unsafe. The
// controller surfaces that refusal; it does not retry around it, and it never
// forces.
func TestProviderRefusalIsSurfacedNotWorkedAround(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	refusal := errors.New("drbdadm primary vol1: State change failed: (-2) Need access to UpToDate data")
	prov.setPromoteErr(refusal)

	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Primary {
		t.Fatal("the controller claimed primary after the provider refused")
	}
	if !errors.Is(got.Err, refusal) {
		t.Fatalf("Err = %v, want it to wrap the provider's refusal", got.Err)
	}
	if !strings.Contains(got.Err.Error(), testVolume) {
		t.Fatalf("the failure %q does not name the volume", got.Err)
	}
	if n := prov.promoteCount(); n != 1 {
		t.Fatalf("Promote was called %d times, want exactly 1: a refusal is not retried within one reconcile", n)
	}
}

// The guard fires when a renewal took most of the TTL to be acknowledged,
// because the deadline is measured from when the request was ISSUED.
func TestPromoteGuardRefusesUnderAlmostExpiredLease(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	// The acquisition itself takes 13 of the 15 seconds it grants, leaving two
	// — less than the five-second guard.
	r.coord.setAcquireHook(func(string) { r.clock.Advance(13 * time.Second) })

	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Phase != PhaseLeading {
		t.Fatalf("Phase = %q; the lease was acquired, just not acted under", got.Phase)
	}
	if got.Primary {
		t.Fatal("the controller promoted under a lease it had almost none of left")
	}
	if !errors.Is(got.Err, ErrLeaseTooShort) {
		t.Fatalf("Err = %v, want ErrLeaseTooShort", got.Err)
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times under an almost-expired lease, want 0", n)
	}
	if len(prov.recorded()) != 0 {
		t.Fatalf("the guard must refuse before touching the provider at all: %v", prov.recorded())
	}

	// A renewal with a normal round trip restores it.
	r.coord.setAcquireHook(nil)
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	r.awaitPrimary(testVolume, true)
}

func TestFailedRenewalDoesNotFenceAndDoesNotMoveTheDeadline(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	first := r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	flaky := errors.New("coordinator timed out")
	r.coord.setRenewErr(flaky)
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	r.clock.awaitTimers(t, 2)

	got := r.status(testVolume)
	if got.Phase != PhaseLeading {
		t.Fatalf("Phase = %q; Done is the authority on the lease, not a renewal error", got.Phase)
	}
	if !errors.Is(got.Err, flaky) {
		t.Fatalf("Err = %v, want it to wrap %v", got.Err, flaky)
	}
	if !got.LeaseDeadline.Equal(first.LeaseDeadline) {
		t.Fatalf("an unacknowledged renewal moved the deadline from %s to %s",
			first.LeaseDeadline, got.LeaseDeadline)
	}

	// An acknowledged one does move it, and clears the warning.
	r.coord.setRenewErr(nil)
	issued := r.clock.Now().Add(r.ctrl.Config().RenewInterval)
	r.clock.Advance(r.ctrl.Config().RenewInterval)

	waitFor(t, func() bool {
		s := r.status(testVolume)
		return s.Err == nil && s.LeaseDeadline.Equal(issued.Add(DefaultLeaseTTL))
	}, "an acknowledged renewal did not move the deadline to %s (status: %+v)",
		issued.Add(DefaultLeaseTTL), r.status(testVolume))
}

// The controller's use of the Coordinator is part of its design: leases, and
// nothing else. No owner key, no CAS-based second mechanism, no watch. This
// pins that, because the cheapest way to reintroduce a stale-state bug is to
// add a key nothing reaps.
func TestControllerUsesLeasesAndNothingElse(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	r.clock.awaitTimers(t, 2)
	r.stop()

	allowed := map[string]bool{"AcquireLease": true, "Renew": true, "Release": true}
	for _, op := range r.coord.recorded() {
		if !allowed[op] {
			t.Fatalf("the controller called Coordinator.%s; it must use leases and nothing else (saw %v)",
				op, r.coord.recorded())
		}
	}
	if r.coord.held(r.leaseKey(testVolume)) {
		t.Fatal("the lease key survived a clean shutdown")
	}
}

// The counterpart on the provider side. roleOnlyProvider panics on every
// filesystem and lifecycle method, so this asserts the positive form: the only
// calls made are the three the settled composition allows.
func TestControllerDrivesRolesAndNeverFilesystems(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	r.stop()

	allowed := map[string]bool{"ReplicationState": true, "Promote": true, "Demote": true}
	for _, op := range prov.recorded() {
		if !allowed[op] {
			t.Fatalf("the controller called provider.%s; it owns the replication role, not the filesystem (saw %v)",
				op, prov.recorded())
		}
	}
}

func TestObserverSeesOrderedTransitions(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)

	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)
	r.coord.expireNow(r.leaseKey(testVolume))
	r.awaitPhase(testVolume, PhaseFenced)
	r.stop()

	phases := r.obs.phases()
	// leading must precede fenced for the same volume: an orchestrator mounts
	// on the first and unmounts on the second, and a reordering would have it
	// unmount a volume it had not yet mounted.
	leading, fenced := -1, -1
	for i, p := range phases {
		if p == PhaseLeading && leading < 0 {
			leading = i
		}
		if p == PhaseFenced && fenced < 0 {
			fenced = i
		}
	}
	if leading < 0 || fenced < 0 {
		t.Fatalf("the observer never saw both leading and fenced: %v", phases)
	}
	if leading > fenced {
		t.Fatalf("the observer saw fenced before leading: %v", phases)
	}
	if last := phases[len(phases)-1]; last != PhaseStopped {
		t.Fatalf("the last observed phase was %q, want %q", last, PhaseStopped)
	}
}

func TestControllerRunsWithoutAnObserver(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, func(cfg *Config) { cfg.Observer = nil })
	r.start(testVolume)
	defer r.stop()

	r.awaitPrimary(testVolume, true)
	if r.obs.count() != 0 {
		t.Fatal("the discarded observer was called")
	}
}

func TestManagerStartsWithAnAlreadyCanceledContext(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := r.ctrl.Manage(ctx, testVolume); err != nil {
		t.Fatalf("Manage with a canceled context returned %v, want nil", err)
	}
	if len(prov.recorded()) != 0 {
		t.Fatalf("a canceled manager touched the provider: %v", prov.recorded())
	}
	if got := r.ctrl.Managed(); len(got) != 0 {
		t.Fatalf("Managed() = %v after the manager returned, want empty", got)
	}
}

func TestControllerManagesSeveralVolumesIndependently(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const other = "vol2"
	done := make(chan error, 2)
	go func() { done <- r.ctrl.Manage(ctx, testVolume) }()
	go func() { done <- r.ctrl.Manage(ctx, other) }()

	r.awaitPrimary(testVolume, true)
	r.awaitPrimary(other, true)

	// Each volume campaigns on its own key, so one node can be primary for one
	// volume and a follower for another.
	if a, b := r.status(testVolume).LeaseKey, r.status(other).LeaseKey; a == b {
		t.Fatalf("both volumes leased the same key %q", a)
	}
	if got := r.ctrl.Managed(); !reflect.DeepEqual(got, []string{testVolume, other}) {
		t.Fatalf("Managed() = %v, want a sorted [%q %q]", got, testVolume, other)
	}

	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Manage returned %v", err)
			}
		case <-time.After(waitTimeout):
			t.Fatal("a manager did not return after cancellation")
		}
	}
}

// A controller that starts on a node already Primary must not announce it as
// serving when the copy may be the wrong side of a divergence. The lease alone
// does not settle that: it decides WHO acts, not whether this copy is the one
// anyone should read.
func TestAnAlreadyPrimaryCopyIsNotAnnouncedWhenItMayBeTheWrongSide(t *testing.T) {
	for _, conn := range []common.ReplConnState{
		common.ReplStateStandalone,
		common.ReplStateSyncTarget,
		common.ReplStateInconsistent,
		common.ReplStateDown,
		common.ReplStateUnknown,
	} {
		t.Run(string(conn), func(t *testing.T) {
			prov := newFakeProvider(conn, common.ReplRolePrimary)
			r := newRig(t, prov, nil)
			r.start(testVolume)
			defer r.stop()

			r.clock.awaitTimers(t, 1)
			got := r.status(testVolume)

			if got.Primary {
				t.Fatalf("a primary copy that is %q was announced as serving; an orchestrator would mount it", conn)
			}
			if r.obs.everPrimary() {
				t.Fatalf("a primary copy that is %q was announced as serving at some point", conn)
			}
			if !errors.Is(got.Err, ErrNotServiceable) {
				t.Fatalf("Err = %v, want ErrNotServiceable", got.Err)
			}
			// The role the provider reported still shows through, so a caller
			// that wants the device's role rather than this controller's
			// authorization can have it.
			if got.Repl.Role != common.ReplRolePrimary {
				t.Fatalf("Repl.Role = %q, want the role the provider reported", got.Repl.Role)
			}
			// Refusing to announce is not a reason to tear a live device out
			// from under whatever is using it.
			if n := prov.demoteCount(); n != 0 {
				t.Fatalf("Demote was called %d times on a refusal to announce, want 0", n)
			}
			if n := prov.promoteCount(); n != 0 {
				t.Fatalf("Promote was called %d times on a copy already primary, want 0", n)
			}
		})
	}
}

// The other half of the asymmetry, and the one a narrower gate would break: an
// established Primary whose peer just died reports "connecting", not
// "uptodate". Withdrawing its announcement would have an orchestrator unmount
// the last surviving copy — the failure high availability exists to prevent.
func TestAnEstablishedPrimaryKeepsServingWhenThePeerDies(t *testing.T) {
	for _, conn := range []common.ReplConnState{
		common.ReplStateUpToDate,
		common.ReplStateSyncSource,
		common.ReplStateConnecting,
	} {
		t.Run(string(conn), func(t *testing.T) {
			prov := newFakeProvider(conn, common.ReplRolePrimary)
			r := newRig(t, prov, nil)
			r.start(testVolume)
			defer r.stop()

			got := r.awaitPrimary(testVolume, true)
			if got.Err != nil {
				t.Fatalf("a serviceable primary reported %v", got.Err)
			}
			if n := prov.promoteCount(); n != 0 {
				t.Fatalf("Promote was called %d times on a copy already primary, want 0", n)
			}
		})
	}
}

// An announcement that a later reconcile disproves has to be withdrawn. Leaving
// it standing would keep an orchestrator mounted on an authorization the
// controller has since found to be false.
func TestAFailedRePromotionWithdrawsTheAnnouncement(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	// It leads and announces.
	r.awaitPrimary(testVolume, true)
	r.clock.awaitTimers(t, 1)

	// The role is lost underneath it — the device was demoted out of band — and
	// the attempt to restore it fails.
	refusal := errors.New("drbdadm primary vol1: State change failed: (-10) State change was refused by peer node")
	prov.setPromoteErr(refusal)
	r.clock.Advance(r.ctrl.Config().RenewInterval)

	var got Status
	waitFor(t, func() bool {
		got = r.status(testVolume)
		return errors.Is(got.Err, refusal)
	}, "the failed re-promotion was never reported (status: %+v)", &got)

	if got.Primary {
		t.Fatal("the announcement survived a re-promotion the controller knows failed")
	}
	if got.Phase != PhaseLeading {
		t.Fatalf("Phase = %q; a failed promotion does not give up the lease", got.Phase)
	}
}

// A leader parked on a refusal keeps that refusal across renewals. Talking to
// the Coordinator successfully says nothing about the volume, so clearing the
// reason there would publish a healthy status for a volume that is still
// refused — and would do it on every cadence tick, which is exactly the churn
// transition compares error text to avoid.
func TestARenewalDoesNotClearAStandingRefusal(t *testing.T) {
	prov := newFakeProvider(common.ReplStateInconsistent, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	first := r.status(testVolume)
	if !errors.Is(first.Err, ErrNotPromotable) {
		t.Fatalf("Err = %v, want ErrNotPromotable", first.Err)
	}
	settled := r.obs.count()

	// Several healthy renewals go by.
	for i := 0; i < 3; i++ {
		r.clock.Advance(r.ctrl.Config().RenewInterval)
		r.clock.awaitTimers(t, i+2)

		got := r.status(testVolume)
		if !errors.Is(got.Err, ErrNotPromotable) {
			t.Fatalf("after renewal %d the refusal was gone: Err = %v", i+1, got.Err)
		}
		if got.Primary {
			t.Fatalf("after renewal %d the controller claimed primary on a refused volume", i+1)
		}
		if !got.LeaseDeadline.After(first.LeaseDeadline) {
			t.Fatalf("after renewal %d the deadline did not move: %s", i+1, got.LeaseDeadline)
		}
	}

	// And the observer was not woken once by any of it. A clear-and-re-set pair
	// per tick would read to an orchestrator as the volume recovering and
	// failing again, three times, for no change at all.
	if got := r.obs.count(); got != settled {
		t.Fatalf("the observer was woken %d extra time(s) by renewals that changed nothing", got-settled)
	}
}

// The renewal error itself IS cleared by a renewal succeeding — that is the one
// thing talking to the Coordinator does resolve.
func TestASuccessfulRenewalClearsOnlyTheRenewalError(t *testing.T) {
	prov := newFakeProvider(common.ReplStateInconsistent, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)

	flaky := errors.New("coordinator timed out")
	r.coord.setRenewErr(flaky)
	r.clock.Advance(r.ctrl.Config().RenewInterval)
	r.clock.awaitTimers(t, 2)

	got := r.status(testVolume)
	if !errors.Is(got.Err, ErrRenewFailed) || !errors.Is(got.Err, flaky) {
		t.Fatalf("Err = %v, want it to wrap both ErrRenewFailed and %v", got.Err, flaky)
	}

	r.coord.setRenewErr(nil)
	r.clock.Advance(r.ctrl.Config().RenewInterval)

	// The renewal warning goes; the refusal underneath comes back, because the
	// reconcile that follows finds the volume still inconsistent.
	waitFor(t, func() bool {
		s := r.status(testVolume)
		return errors.Is(s.Err, ErrNotPromotable) && !errors.Is(s.Err, ErrRenewFailed)
	}, "the renewal error was not replaced by the standing refusal (status: %+v)", r.status(testVolume))
}

// The renewal cadence is measured against the acknowledged DEADLINE, not
// against the moment the last call returned. An acquire that consumed most of
// the TTL leaves far less than a full interval of lease; waiting one anyway
// would let it expire without a single attempt to keep it.
func TestRenewalIsScheduledAgainstTheDeadlineNotTheReturn(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)

	// The acquisition consumes 11 of the 15 seconds it grants, so four remain
	// where the cadence would otherwise assume fifteen.
	r.coord.setAcquireHook(func(string) { r.clock.Advance(11 * time.Second) })
	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	r.coord.setAcquireHook(nil)

	renewsBefore := countOp(r.coord.recorded(), "Renew")

	// Half of what is left — two seconds — not the five-second interval. With
	// the cadence measured from the return this tick would fall short and no
	// renewal would happen at all.
	r.clock.Advance(2 * time.Second)
	waitFor(t, func() bool { return countOp(r.coord.recorded(), "Renew") > renewsBefore },
		"no renewal was attempted two seconds into a lease with only four seconds left")

	// And the renewal restored a full deadline, so the cadence returns to the
	// configured interval.
	got := r.status(testVolume)
	if want := r.clock.Now().Add(DefaultLeaseTTL); !got.LeaseDeadline.Equal(want) {
		t.Fatalf("LeaseDeadline = %s, want %s", got.LeaseDeadline, want)
	}
}

func TestRenewDelay(t *testing.T) {
	clock := newTestClock()
	ctrl, err := New(newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary),
		newFakeCoordinator(), Config{NodeID: testNode, Clock: clock})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := clock.Now()
	interval := ctrl.Config().RenewInterval

	tests := []struct {
		name      string
		remaining time.Duration
		want      time.Duration
	}{
		{"a healthy lease waits the configured interval", DefaultLeaseTTL, interval},
		{"exactly twice the interval still waits the interval", 2 * interval, interval},
		{"less than twice the interval waits half of what is left", 4 * time.Second, 2 * time.Second},
		{"a nearly spent lease waits a nearly spent half", time.Second, 500 * time.Millisecond},
		{"a nearly spent half is floored", 10 * time.Millisecond, minRenewDelay},
		{"a deadline already reached takes the floor, not zero", 0, minRenewDelay},
		{"and so does one already passed", -time.Minute, minRenewDelay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ctrl.renewDelay(now.Add(tt.remaining)); got != tt.want {
				t.Fatalf("renewDelay(%s remaining) = %s, want %s", tt.remaining, got, tt.want)
			}
		})
	}
}

// The promote guard is itself a check-then-act, and the act is the promotion.
// A replication-state read slow enough to consume the remaining lease leaves
// the first check answering for a world that has moved, so the guard is asked
// again at the point it governs.
func TestTheGuardIsRecheckedAfterASlowStateRead(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	// The read consumes 12 of the 15 seconds the lease was granted for, so the
	// three that remain are under the five-second guard — but only by the time
	// the read returns.
	var once atomic.Bool
	r := newRig(t, prov, nil)
	prov.setReplHook(func(context.Context) {
		if once.CompareAndSwap(false, true) {
			r.clock.Advance(12 * time.Second)
		}
	})

	r.start(testVolume)
	defer r.stop()

	r.clock.awaitTimers(t, 1)
	got := r.status(testVolume)

	if got.Primary {
		t.Fatal("the controller promoted under a lease that ran out while it was reading")
	}
	if !errors.Is(got.Err, ErrLeaseTooShort) {
		t.Fatalf("Err = %v, want ErrLeaseTooShort", got.Err)
	}
	if n := prov.promoteCount(); n != 0 {
		t.Fatalf("Promote was called %d times after the guard had gone stale, want 0", n)
	}
	// The read itself did happen — this is the second check, not the first.
	if n := countOp(prov.recorded(), "ReplicationState"); n == 0 {
		t.Fatal("the replication state was never read; this test must exercise the SECOND guard")
	}
	if got.Repl.Conn != common.ReplStateUpToDate {
		t.Fatalf("Repl.Conn = %q; the read's result is still recorded", got.Repl.Conn)
	}
}

// Status must not announce Primary alongside a role of secondary. The role the
// controller just established moves with the announcement, so a caller reading
// the two together does not have to guess which one to believe.
func TestAPromotionUpdatesTheReportedRole(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)
	r := newRig(t, prov, nil)
	r.start(testVolume)
	defer r.stop()

	got := r.awaitPrimary(testVolume, true)
	if got.Repl.Role != common.ReplRolePrimary {
		t.Fatalf("Repl.Role = %q while Primary is announced; the status contradicts itself", got.Repl.Role)
	}
	if got.Repl.Conn != common.ReplStateUpToDate {
		t.Fatalf("Repl.Conn = %q, want the connection state the read reported", got.Repl.Conn)
	}
	// The observer saw the same thing, since that is what an orchestrator acts on.
	for _, s := range r.obs.seenCopy() {
		if s.Primary && s.Repl.Role != common.ReplRolePrimary {
			t.Fatalf("an announced status carried Repl.Role %q", s.Repl.Role)
		}
	}
}
