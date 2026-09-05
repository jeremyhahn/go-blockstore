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

package mountguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// plainTable is a mount table with none of the optional propagation half — the
// shape a caller outside this module can legitimately build, since
// PropagationOf is deliberately not on Table.
type plainTable struct{}

func (plainTable) MountPointsFor(context.Context, string) ([]string, error)        { return nil, nil }
func (plainTable) VisibleMountPointsFor(context.Context, string) ([]string, error) { return nil, nil }

// readerTable answers the propagation question from a script, and records the
// context it was asked on — which is the only way to see that the rollback did
// not inherit a dead one.
type readerTable struct {
	plainTable

	id         uint32
	propagates bool
	spelling   string
	err        error

	calls   int
	lastErr error
}

func (r *readerTable) PropagationOf(ctx context.Context, _, _ string) (uint32, bool, string, error) {
	r.calls++
	r.lastErr = ctx.Err()
	return r.id, r.propagates, r.spelling, r.err
}

func TestPolicyVocabulary(t *testing.T) {
	for spelling, want := range map[string]Policy{"unchecked": Unchecked, "shared": Shared} {
		got, known := Parse(spelling)
		if !known || got != want {
			t.Errorf("Parse(%q) = %v, %v; want %v, true", spelling, got, known, want)
		}
		if got.String() != spelling {
			t.Errorf("%v.String() = %q, want %q: the parser and the rendering must not drift", got, got.String(), spelling)
		}
		if !got.Valid() {
			t.Errorf("%v.Valid() = false", got)
		}
	}

	if _, known := Parse("share"); known {
		t.Error(`Parse("share") reported a misspelling as known, which would turn a typo into "off"`)
	}

	// The fail-open an exported integer type makes reachable: every comparison
	// in this package is against Shared, so an unknown value behaves exactly
	// like "off" unless somebody refuses it.
	unknown := Policy(2)
	if unknown.Valid() {
		t.Error("Policy(2).Valid() = true, so a wrong number would silently disable the guard")
	}
	if unknown.String() != "unknown(2)" {
		t.Errorf("Policy(2).String() = %q, want it to show the number a caller wrote", unknown.String())
	}

	if got := Spellings(); len(got) != 2 || got[0] != "shared" || got[1] != "unchecked" {
		t.Errorf("Spellings() = %v, want the accepted values in a stable order", got)
	}
}

func TestCanReport(t *testing.T) {
	if (Guard{}).CanReport() {
		t.Error("a guard with no table reports that it can answer")
	}
	if (Guard{Table: plainTable{}}).CanReport() {
		t.Error("a table without PropagationOf reports that it can answer")
	}
	if !(Guard{Table: &readerTable{}}).CanReport() {
		t.Error("a table with PropagationOf reports that it cannot answer")
	}
}

// TestVerifyDoesNothingWhenTheGuardIsOff is the off-by-default behavior: no
// lookup happens at all, so a provider that never turned the guard on does not
// pay for it or fail because of it.
func TestVerifyDoesNothingWhenTheGuardIsOff(t *testing.T) {
	table := &readerTable{err: errors.New("the table must not be read")}

	id, err := (Guard{Policy: Unchecked, Table: table}).Verify(context.Background(), "/dev/x", "/mnt/x")
	if id != 0 || err != nil {
		t.Fatalf("Verify with the guard off = %d, %v; want 0, nil", id, err)
	}
	if table.calls != 0 {
		t.Errorf("the mount table was read %d times with the guard off", table.calls)
	}
}

// TestVerifyRefusesRatherThanPassesWhenItCannotSee is the property the whole
// package exists for: a guard that cannot check must not report what a passing
// guard reports.
func TestVerifyRefusesRatherThanPassesWhenItCannotSee(t *testing.T) {
	unreadable := errors.New("opening /proc/self/mountinfo: permission denied")

	for name, tc := range map[string]struct {
		guard   Guard
		wantErr error
	}{
		"the table cannot answer the question at all": {
			guard:   Guard{Policy: Shared, Table: plainTable{}},
			wantErr: ErrTableCannotReport,
		},
		// A provider that never set a table. pkg/drbd refuses one at
		// construction and pkg/local skips the check for it, so this is the
		// branch neither provider can reach — and the one where a guard that
		// treated "no table" as "nothing to worry about" would fail open.
		"there is no table": {
			guard:   Guard{Policy: Shared},
			wantErr: ErrTableCannotReport,
		},
		"the table could not be read": {
			guard:   Guard{Policy: Shared, Table: &readerTable{err: unreadable}},
			wantErr: unreadable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.guard.Verify(context.Background(), "/dev/x", "/mnt/x")

			var capErr *preflight.CapabilityError
			if !errors.As(err, &capErr) {
				t.Fatalf("Verify = %v, want a preflight.CapabilityError", err)
			}
			if capErr.Capability != preflight.CapabilityMountPropagation {
				t.Errorf("Capability = %q, want %q", capErr.Capability, preflight.CapabilityMountPropagation)
			}
			if capErr.Cause != preflight.CauseIndeterminate {
				t.Errorf("Cause = %q, want %q", capErr.Cause, preflight.CauseIndeterminate)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Verify = %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyRefusesAMountThatDoesNotPropagate(t *testing.T) {
	table := &readerTable{id: 7, propagates: false, spelling: "private"}

	id, err := (Guard{Policy: Shared, Table: table}).Verify(context.Background(), "/dev/x", "/mnt/x")
	if id != 7 {
		t.Errorf("id = %d, want 7: the rollback needs the identity even on a refusal", id)
	}
	var capErr *preflight.CapabilityError
	if !errors.As(err, &capErr) || capErr.Cause != preflight.CauseMountNotPropagated {
		t.Fatalf("Verify of a private mount = %v, want CauseMountNotPropagated", err)
	}
	if !strings.Contains(capErr.Probe, "private") {
		t.Errorf("Probe = %q, want it to name what the kernel reported", capErr.Probe)
	}
}

func TestVerifyAcceptsAMountThatPropagates(t *testing.T) {
	table := &readerTable{id: 9, propagates: true, spelling: "shared:214"}

	id, err := (Guard{Policy: Shared, Table: table}).Verify(context.Background(), "/dev/x", "/mnt/x")
	if id != 9 || err != nil {
		t.Fatalf("Verify of a shared mount = %d, %v; want 9, nil", id, err)
	}
}

// TestVerifyReadsTheTableEvenOnADeadContext is the ordering that keeps a
// canceled caller from leaving an unidentifiable mount behind.
//
// Once mount(2) has returned, verifying and unwinding are COMPLETION work. A
// caller whose deadline passed in that instant would otherwise leave a mount
// that was never verified and never cleaned up, because the read that would
// identify it fails first. So the read happens, and THEN the caller is told they
// gave up — with the identity in hand.
func TestVerifyReadsTheTableEvenOnADeadContext(t *testing.T) {
	table := &readerTable{id: 11, propagates: true, spelling: "shared:1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	id, err := (Guard{Policy: Shared, Table: table}).Verify(ctx, "/dev/x", "/mnt/x")
	if table.calls != 1 {
		t.Fatalf("the table was read %d times on a canceled context, want 1", table.calls)
	}
	if table.lastErr != nil {
		t.Errorf("the lookup ran on a context reporting %v, want one detached from the caller's", table.lastErr)
	}
	if id != 11 {
		t.Errorf("id = %d, want 11: the mount the caller no longer wants must still be identifiable", id)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify = %v, want it to report the cancellation", err)
	}
}

// TestUnwindRemovesTheMountItRefused is the plain path: the target is still this
// call's mount, so it goes.
func TestUnwindRemovesTheMountItRefused(t *testing.T) {
	table := &readerTable{id: 5}
	finding := errors.New("the mount is private")

	var unmounted []string
	err := (Guard{Policy: Shared, Table: table}).Unwind(context.Background(), "/dev/x", "/mnt/x", 5, finding,
		func(_ context.Context, target string) error {
			unmounted = append(unmounted, target)
			return nil
		})

	if !errors.Is(err, finding) {
		t.Errorf("Unwind = %v, want the guard's finding back", err)
	}
	if len(unmounted) != 1 || unmounted[0] != "/mnt/x" {
		t.Errorf("unmounted = %v, want exactly the refused target", unmounted)
	}
}

// TestUnwindLeavesAMountThatIsNoLongerOurs covers every way the rollback can
// decline, and each one keeps the finding: the reason the mount is there and
// what happened to the cleanup are two facts about one event, and an operator
// needs both.
func TestUnwindLeavesAMountThatIsNoLongerOurs(t *testing.T) {
	unreadable := errors.New("the table went away")
	umountFailed := errors.New("umount: target is busy")

	for name, tc := range map[string]struct {
		guard       Guard
		umount      func(context.Context, string) error
		wantErr     error
		wantUnmount bool
	}{
		"the table cannot answer": {
			guard:   Guard{Policy: Shared, Table: plainTable{}},
			wantErr: ErrTableCannotReport,
		},
		"the table could not be read": {
			guard:   Guard{Policy: Shared, Table: &readerTable{err: unreadable}},
			wantErr: unreadable,
		},
		// The case (device, path) cannot see: a SECOND mount of the same device
		// stacked on the same path. Unmounting by path would detach theirs.
		"a different mount is at the target now": {
			guard:   Guard{Policy: Shared, Table: &readerTable{id: 6}},
			wantErr: ErrTargetTakenOver,
		},
		"the unmount itself failed": {
			guard:       Guard{Policy: Shared, Table: &readerTable{id: 5}},
			umount:      func(context.Context, string) error { return umountFailed },
			wantErr:     umountFailed,
			wantUnmount: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			finding := errors.New("the mount is private")
			called := false
			umount := tc.umount
			if umount == nil {
				umount = func(context.Context, string) error { return nil }
			}
			wrapped := func(ctx context.Context, target string) error {
				called = true
				return umount(ctx, target)
			}

			err := tc.guard.Unwind(context.Background(), "/dev/x", "/mnt/x", 5, finding, wrapped)
			if !errors.Is(err, finding) {
				t.Errorf("Unwind = %v, want the guard's finding carried through", err)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Unwind = %v, want it to also report %v", err, tc.wantErr)
			}
			if called != tc.wantUnmount {
				t.Errorf("umount called = %v, want %v", called, tc.wantUnmount)
			}
		})
	}
}

// TestUnwindRunsOnItsOwnContext is the review finding that makes the rollback
// work at all in the case it is most likely to run: the caller's context already
// dead. Reusing it would fail the mount-table read instantly and leave behind
// exactly the mount this exists to remove.
func TestUnwindRunsOnItsOwnContext(t *testing.T) {
	table := &readerTable{id: 5}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var unmountCtxErr error
	err := (Guard{Policy: Shared, Table: table}).Unwind(ctx, "/dev/x", "/mnt/x", 5, errors.New("refused"),
		func(ctx context.Context, _ string) error {
			unmountCtxErr = ctx.Err()
			return nil
		})
	if err == nil {
		t.Fatal("Unwind = nil, want the finding back")
	}
	if table.lastErr != nil {
		t.Errorf("the mount-table read ran on a context reporting %v, want a detached one", table.lastErr)
	}
	if unmountCtxErr != nil {
		t.Errorf("the unmount ran on a context reporting %v, want a detached one", unmountCtxErr)
	}
}

// TestUnwindContextIsBounded keeps the detachment from becoming a cleanup that
// can hang forever.
func TestUnwindContextIsBounded(t *testing.T) {
	ctx, cancel := UnwindContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("UnwindContext returned a context with no deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > unwindTimeout {
		t.Errorf("deadline is %v away, want it within (0, %v]", remaining, unwindTimeout)
	}
}
