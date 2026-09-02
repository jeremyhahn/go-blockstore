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

package local

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// mountable builds a provider whose volume is attached and formatted, which is
// the state Mount needs before propagation is even reachable.
func mountable(t *testing.T, opts ...func(*Options)) (*Provider, *fakeRunner) {
	t.Helper()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	return newTestProvider(t, runner, opts...), runner
}

// requireShared is the deployment that hands mounts to a workload elsewhere.
func requireShared(o *Options) { o.MountPropagation = MountPropagationShared }

// TestMountRefusesAPrivateMountWhenPropagationIsRequired is the whole point of
// the guard: mount(2) succeeded, this provider is satisfied, and the workload in
// its own namespace would find an empty directory with no error anywhere.
func TestMountRefusesAPrivateMountWhenPropagationIsRequired(t *testing.T) {
	p, runner := mountable(t, requireShared)
	// The mounter records the mount; the mount table reports it private, which
	// is the ordinary state of a mount and the failure in this deployment.
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a private mount in a deployment that requires propagation")
	}
	if !errors.Is(err, preflight.ErrMountNotPropagated) {
		t.Fatalf("Mount = %v, want ErrMountNotPropagated", err)
	}

	// The finding has to name the mount and carry the fix, because it is the
	// only artifact anybody sees.
	for _, want := range []string{"/mnt/data", "private", "Bidirectional", "rshared"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the finding does not mention %q: %v", want, err)
		}
	}
}

// TestMountAcceptsASharedMount is the other half of the mutation requirement:
// the guard must not reject a correct environment.
func TestMountAcceptsASharedMount(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}).
		withPropagation("/mnt/data", "shared:42")

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a shared mount = %v, want nil", err)
	}
	if got := runner.mountCalls(); len(got) != 1 {
		t.Fatalf("mounted %d times, want once", len(got))
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("a verified mount was unwound: %v", got)
	}
}

// TestMountDoesNotCheckPropagationByDefault pins the default. A mount is
// private on an ordinary host and that is correct there; a guard that refused
// every non-containerized deployment would be rejecting a correct environment.
func TestMountDoesNotCheckPropagationByDefault(t *testing.T) {
	p, runner := mountable(t)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err != nil {
		t.Fatalf("Mount = %v, want nil with propagation unchecked", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("something was unmounted with the guard off: %v", got)
	}
}

// TestARefusedMountIsUnwound covers the state Mount leaves behind. A caller told
// the operation failed must not be left with a filesystem mounted that nothing
// will ever unmount.
func TestARefusedMountIsUnwound(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err == nil {
		t.Fatal("Mount accepted a private mount")
	}
	got := runner.unmountCalls()
	if len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("unmounted %v, want the refused mount to be unwound", got)
	}
}

// TestARefusedMountReportsAFailedUnwind keeps both facts. The finding is why the
// mount is there; a failure to remove it is a second fact about the same event,
// and losing either one leaves an operator without the thing they need.
func TestARefusedMountReportsAFailedUnwind(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	runner.failUnmount(errors.New("target is busy"))

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a private mount")
	}
	if !errors.Is(err, preflight.ErrMountNotPropagated) {
		t.Errorf("the propagation finding was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "target is busy") {
		t.Errorf("the failed unwind was lost: %v", err)
	}
}

// TestMountFailsClosedWhenPropagationCannotBeRead is the guard's own failure
// mode. A check that cannot run is a failure, not a pass: reporting success
// there converts an unknown into a green light exactly where somebody is
// relying on the check.
func TestMountFailsClosedWhenPropagationCannotBeRead(t *testing.T) {
	cases := map[string]error{
		"unreadable proc file": &mountinfo.ReadError{Path: mountinfo.ProcPath, Err: os.ErrPermission},
		"malformed record": &mountinfo.ParseError{
			Line: 12, Text: "1 2 8:1 /", Err: mountinfo.ErrTooFewFields,
		},
	}

	for name, tableErr := range cases {
		t.Run(name, func(t *testing.T) {
			p, runner := mountable(t, requireShared)
			runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}).
				failMountTable(tableErr)

			err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
			if err == nil {
				t.Fatal("Mount accepted a mount whose propagation could not be read")
			}
			if !errors.Is(err, preflight.ErrIndeterminate) {
				t.Errorf("Mount = %v, want ErrIndeterminate", err)
			}
			if !errors.Is(err, tableErr) {
				t.Errorf("the underlying failure was lost: %v", err)
			}
			// And the remedy points at the check, not at the mount.
			if !strings.Contains(err.Error(), "/proc") {
				t.Errorf("the remedy does not point at /proc: %v", err)
			}
		})
	}
}

// TestMountFailsClosedWhenTheMountIsNotThere covers the case that looks like a
// bug in this provider and would be read as one: mount(2) reported success and
// the kernel's table does not show the mount. Nothing is a pass here.
func TestMountFailsClosedWhenTheMountIsNotThere(t *testing.T) {
	p, runner := mountable(t, requireShared)
	// No withMounts: the mounter accepts the mount and the table never sees it.
	_ = runner

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a mount the kernel's table does not have")
	}
	if !errors.Is(err, mountinfo.ErrNotMounted) {
		t.Errorf("Mount = %v, want it to carry ErrNotMounted", err)
	}
	if !errors.Is(err, preflight.ErrIndeterminate) {
		t.Errorf("Mount = %v, want ErrIndeterminate", err)
	}
}

// TestPropagationPolicySpellings covers the settings surface, where a
// misspelling has to be refused rather than quietly turning the guard off.
func TestPropagationPolicySpellings(t *testing.T) {
	for spelling, want := range map[string]MountPropagationPolicy{
		"unchecked": MountPropagationUnchecked,
		"shared":    MountPropagationShared,
	} {
		t.Run(spelling, func(t *testing.T) {
			p, err := NewFromSettings(map[string]string{
				SettingVolumeGroup:      "vg0",
				SettingPreflight:        "off",
				SettingMountPropagation: spelling,
			})
			if err != nil {
				t.Fatalf("NewFromSettings: %v", err)
			}
			if p.mountPropagation != want {
				t.Errorf("policy = %v, want %v", p.mountPropagation, want)
			}
		})
	}

	_, err := NewFromSettings(map[string]string{
		SettingVolumeGroup:      "vg0",
		SettingPreflight:        "off",
		SettingMountPropagation: "bidirectional",
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("a misspelled policy = %v, want common.ErrInvalidArgument", err)
	}
	// The refusal has to say what IS accepted, or the operator guesses again.
	for _, want := range []string{"unchecked", "shared"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not list %q: %v", want, err)
		}
	}
}

// TestPropagationDefaultsToUnchecked pins the zero value at the level a caller
// building Options by hand meets it.
func TestPropagationDefaultsToUnchecked(t *testing.T) {
	p, err := NewFromSettings(map[string]string{SettingVolumeGroup: "vg0", SettingPreflight: "off"})
	if err != nil {
		t.Fatalf("NewFromSettings: %v", err)
	}
	if p.mountPropagation != MountPropagationUnchecked {
		t.Errorf("policy = %v, want unchecked", p.mountPropagation)
	}
}

// tableWithoutPropagation is a MountTable of the shape an external caller could
// reasonably have written before the propagation guard existed: the two lookups
// and nothing else.
type tableWithoutPropagation struct{ mounted map[string][]string }

func (t tableWithoutPropagation) MountPointsFor(_ context.Context, device string) ([]string, error) {
	return t.mounted[device], nil
}

func (t tableWithoutPropagation) VisibleMountPointsFor(ctx context.Context, device string) ([]string, error) {
	return t.MountPointsFor(ctx, device)
}

// The compatibility property the optional interface exists for, asserted at
// COMPILE time: a caller's own mount table, written before the propagation
// guard, must still satisfy MountTable. If PropagationAt were a required method
// this line would not build — which is exactly what would happen to that
// caller's code.
var _ MountTable = tableWithoutPropagation{}

// TestAMountTableWithoutPropagationIsNotAPropagationReader keeps the fixture
// honest. The compile-time assertion above proves the compatibility; this
// proves the fixture is actually the shape the other tests need it to be,
// because a fixture that quietly grew the method would make them pass while
// testing nothing.
func TestAMountTableWithoutPropagationIsNotAPropagationReader(t *testing.T) {
	if _, isReader := any(tableWithoutPropagation{}).(MountPropagationReader); isReader {
		t.Error("the fixture implements the optional half, so the tests using it prove nothing")
	}
}

// TestNewRefusesPropagationOverATableThatCannotReportIt is the other half of
// making the seam optional, and it is refused at CONSTRUCTION.
//
// Skipping the check for a table that cannot answer would turn an injected seam
// into a way to switch a security guard off silently. Discovering it at the
// first Mount is barely better: the mount has already happened, the guard
// cannot judge it, and the rollback cannot identify it either — so Mount would
// return an error over a filesystem it left mounted. A configuration that
// cannot work is refused before it can mount anything.
func TestNewRefusesPropagationOverATableThatCannotReportIt(t *testing.T) {
	_, err := New(Options{
		VolumeGroup:      "vg0",
		Preflight:        PreflightOff,
		LockDir:          t.TempDir(),
		Runner:           newFakeRunner(),
		MountPropagation: MountPropagationShared,
		MountTable:       tableWithoutPropagation{},
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New = %v, want common.ErrInvalidArgument", err)
	}
	for _, want := range []string{SettingMountPropagation, "MountPropagationReader"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestNewAcceptsATableWithoutPropagationWhenTheGuardIsOff is the case the
// optional interface is FOR: a caller's own mount table, and a guard they never
// turned on.
func TestNewAcceptsATableWithoutPropagationWhenTheGuardIsOff(t *testing.T) {
	if _, err := New(Options{
		VolumeGroup: "vg0", Preflight: PreflightOff, LockDir: t.TempDir(),
		Runner:     newFakeRunner(),
		MountTable: tableWithoutPropagation{},
	}); err != nil {
		t.Fatalf("New with the guard off = %v, want nil", err)
	}
}

// TestPropagationUncheckedWithATableThatCannotAnswer is the case the optional
// interface is FOR: the guard is off, so a table without it is simply used.
func TestPropagationUncheckedWithATableThatCannotAnswer(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner, func(o *Options) {
		o.MountTable = tableWithoutPropagation{mounted: map[string][]string{"/dev/vg0/data": {"/mnt/data"}}}
	})

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err != nil {
		t.Fatalf("Mount = %v, want nil with the guard off", err)
	}
}

// TestARefusedMountIsNotUnwoundOverAnotherFilesystem is the rollback's own
// version of the overmount hazard.
//
// Between this provider's mount succeeding and the propagation check refusing
// it, anything on the host can mount over the target — the per-volume lock does
// not stop a process that never asked this provider for anything. umount(2)
// takes a path and detaches what is VISIBLE there, so a rollback that did not
// look would tidy up by taking somebody else's filesystem down.
func TestARefusedMountIsNotUnwoundOverAnotherFilesystem(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}).
		overMount("/mnt/data", "/dev/sdb1")

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a mount it could not verify")
	}

	// The guard now catches this EARLIER than the rollback did: asked about
	// this device at this path, the mount table reports that something else is
	// visible there, so no propagation verdict is reached at all. Reading the
	// interloper's propagation would have been the fail-open — a shared thing
	// landing on top would have made a private mount pass.
	if !errors.Is(err, mountinfo.ErrNotVisibleThere) {
		t.Errorf("the finding does not say another filesystem is visible there: %v", err)
	}
	if !errors.Is(err, preflight.ErrIndeterminate) {
		t.Errorf("an unverifiable mount is not reported as indeterminate: %v", err)
	}
	// And the safety property, unchanged: nothing was unmounted.
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Fatalf("unmounted %v; the filesystem on top is not ours to detach", got)
	}
}

// TestARefusedMountIsNotUnwoundAfterItIsRestacked is the hazard (device, path)
// cannot see: a SECOND mount of the SAME device on the SAME path.
//
// Every string matches — same device, same target — so a rollback comparing
// those would unmount the other actor's mount and leave the refused one
// underneath. The kernel's identity for the mount instance is what tells them
// apart, and it is what the rollback compares.
func TestARefusedMountIsNotUnwoundAfterItIsRestacked(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})

	// The mount is replaced in place while the guard is between its verdict and
	// its rollback: same device, same path, different mount.
	runner.onUnmountTableLookup(func() { runner.restack("/dev/vg0/data", "/mnt/data") })

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a private mount")
	}
	if !errors.Is(err, preflight.ErrMountNotPropagated) {
		t.Errorf("the propagation finding was lost: %v", err)
	}
	if !errors.Is(err, errUnwindTargetTakenOver) {
		t.Errorf("the un-done rollback was not reported: %v", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Fatalf("unmounted %v; that mount is no longer the one this call made", got)
	}
}

// TestARefusedMountReportsAnUnreadableTableDuringUnwind covers the check the
// rollback itself depends on. It cannot unmount safely without knowing what is
// at the target, so a table it cannot read stops the rollback rather than
// letting it proceed blind.
func TestARefusedMountReportsAnUnreadableTableDuringUnwind(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}).
		withPropagation("/mnt/data", "private")

	// Readable for the guard's own lookup, then unreadable for the rollback's.
	runner.failMountTableAfter(1, &mountinfo.ReadError{Path: mountinfo.ProcPath, Err: os.ErrPermission})

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount accepted a private mount")
	}
	if !errors.Is(err, preflight.ErrMountNotPropagated) {
		t.Errorf("the propagation finding was lost: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("the failed rollback lookup was lost: %v", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("unmounted %v without knowing what was at the target", got)
	}
}

// TestARefusedMountIsUnwoundEvenWhenTheCallerGaveUp is the compensating
// action's own rule, and the likeliest way to reach the rollback at all.
//
// The guard reports a dead context as a refusal, so a caller whose deadline
// passes just after mount(2) succeeds arrives here with ctx already gone. A
// rollback that reused it would find the mount table unreadable, do nothing,
// and leave behind exactly the mount it exists to remove — while the code reads
// as though it had removed it. pkg/drbd learned this on a borrowed lvchange;
// the rule is the same for a syscall.
func TestARefusedMountIsUnwoundEvenWhenTheCallerGaveUp(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The caller gives up in the window between mount(2) returning and anything
	// being checked, which is the window this is about.
	runner.OnMount(cancel)

	err := p.Mount(ctx, "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount succeeded under a context that died during it")
	}
	// The mount is private, so that is the finding — the more actionable of the
	// two, and reached because the verification runs on a context of its own.
	if !errors.Is(err, preflight.ErrMountNotPropagated) {
		t.Errorf("Mount = %v, want the propagation finding", err)
	}

	got := runner.unmountCalls()
	if len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("unmounted %v, want the mount unwound despite the dead context", got)
	}
}

// TestAVerifiedMountIsStillUnwoundForACallerWhoGaveUp covers the other half:
// the mount is fine, and the caller stopped wanting it.
//
// The verification runs on its own context, so it reaches a verdict; the
// CALLER's context is then checked, and a Mount that returns an error must not
// leave a filesystem mounted. Both facts are needed — a cancellation reported
// without the rollback would leave the mount, and a rollback without the report
// would look like success.
func TestAVerifiedMountIsStillUnwoundForACallerWhoGaveUp(t *testing.T) {
	p, runner := mountable(t, requireShared)
	runner.withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}).
		withPropagation("/mnt/data", "shared:7")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.OnMount(cancel)

	err := p.Mount(ctx, "data", "/mnt/data", common.MountOptions{})
	if err == nil {
		t.Fatal("Mount succeeded under a context that died during it")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Mount = %v, want it to carry the cancellation", err)
	}
	got := runner.unmountCalls()
	if len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("unmounted %v, want the verified mount unwound for a caller who gave up", got)
	}
}

// TestNewRefusesAnUnknownPropagationPolicy is the fail-open the settings path
// alone does not close.
//
// MountPropagationPolicy is an exported integer type, so a caller building
// Options by hand can write a value that is neither of the two. Every
// comparison in this package is against MountPropagationShared, so an unknown
// value would behave exactly like "off" — the guard silently absent because the
// value asking for it was not one this package defines, and Posture reporting
// it as NOT CHECKED as though that had been the choice.
func TestNewRefusesAnUnknownPropagationPolicy(t *testing.T) {
	_, err := New(Options{
		VolumeGroup:      "vg0",
		Preflight:        PreflightOff,
		LockDir:          t.TempDir(),
		MountPropagation: MountPropagationPolicy(2),
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with an unknown policy = %v, want common.ErrInvalidArgument", err)
	}
	// The refusal has to say what IS accepted, like the settings path does.
	for _, want := range []string{"unchecked", "shared"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not list %q: %v", want, err)
		}
	}
}

// TestBothPolicesAreAccepted is the other half: the check must not refuse the
// values it exists to allow.
func TestBothPoliciesAreAccepted(t *testing.T) {
	for _, policy := range []MountPropagationPolicy{MountPropagationUnchecked, MountPropagationShared} {
		if _, err := New(Options{
			VolumeGroup: "vg0", Preflight: PreflightOff, LockDir: t.TempDir(),
			MountPropagation: policy,
		}); err != nil {
			t.Errorf("New with %s = %v, want nil", policy, err)
		}
	}
}
