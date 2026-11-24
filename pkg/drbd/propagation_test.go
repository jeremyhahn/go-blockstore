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

//go:build drbd

package drbd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// requirePropagation is the tweak that turns the guard on, so a test does not
// have to remember the setting's spelling.
func requirePropagation(settings map[string]string) {
	settings[SettingMountPropagation] = "shared"
}

// mountedProvider builds a Primary provisioned volume with a filesystem; the mount and the mount table are separate fakes.
func mountedProvider(t *testing.T, tweak func(map[string]string)) (*Provider, *fakeRunner) {
	t.Helper()
	p, r, _ := newTestProviderWith(t, tweak)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")
	r.scriptMount("/dev/drbd0", testMountPoint)
	return p, r
}

// TestMountDoesNotCheckPropagationByDefault: a private mount succeeds with the guard off.
func TestMountDoesNotCheckPropagationByDefault(t *testing.T) {
	p, r := mountedProvider(t, nil)

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount with the guard at its default = %v, want nil", err)
	}
	if _, _, _, err := r.PropagationOf(context.Background(), "/dev/drbd0", testMountPoint); err != nil {
		t.Fatalf("the fixture's mount should be readable: %v", err)
	}
}

// TestMountRefusesAPrivateMountWhenPropagationIsRequired is the guard doing the
// thing it was extended here to do.
func TestMountRefusesAPrivateMountWhenPropagationIsRequired(t *testing.T) {
	p, _ := mountedProvider(t, requirePropagation)

	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	var capErr *preflight.CapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("Mount of a private mount = %v, want a preflight.CapabilityError", err)
	}
	if capErr.Capability != preflight.CapabilityMountPropagation {
		t.Errorf("Capability = %q, want %q", capErr.Capability, preflight.CapabilityMountPropagation)
	}
	if capErr.Cause != preflight.CauseMountNotPropagated {
		t.Errorf("Cause = %q, want %q", capErr.Cause, preflight.CauseMountNotPropagated)
	}
	if !strings.Contains(capErr.Probe, "private") {
		t.Errorf("Probe = %q, want it to name the propagation the kernel reported", capErr.Probe)
	}
}

// TestMountAcceptsASharedMountWhenPropagationIsRequired is the other half: the
// guard passes what it is supposed to pass, so the refusal above is evidence
// about propagation rather than about the guard being on.
func TestMountAcceptsASharedMountWhenPropagationIsRequired(t *testing.T) {
	p, r := mountedProvider(t, requirePropagation)
	r.withPropagation(testMountPoint, "shared:214")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a shared mount = %v, want nil", err)
	}
}

// TestMountUnwindsAMountItRefuses is why the refusal is not just an error
// return. The caller has been told the operation failed, so a filesystem left
// mounted is one nothing will ever unmount.
func TestMountUnwindsAMountItRefuses(t *testing.T) {
	p, r, m := newTestProviderWith(t, requirePropagation)
	provision(t, p, r, defaultSpec())
	r.reset()
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")
	r.scriptMount("/dev/drbd0", testMountPoint)

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err == nil {
		t.Fatal("Mount of a private mount succeeded")
	}
	if got := m.UnmountCalls(); len(got) != 1 || got[0] != testMountPoint {
		t.Fatalf("unmount calls = %v, want exactly one at %q: a refused mount must not be left mounted", got, testMountPoint)
	}
}

// TestMountRefusesRatherThanPassesWhenPropagationCannotBeRead: the cause is CauseIndeterminate.
func TestMountRefusesRatherThanPassesWhenPropagationCannotBeRead(t *testing.T) {
	unreadable := errors.New("opening /proc/self/mountinfo: permission denied")

	for name, tc := range map[string]struct {
		arrange func(r *fakeRunner)
		wantErr error
	}{
		// The table itself fails — /proc unreadable, the file unparseable.
		"the table cannot be read": {
			arrange: func(r *fakeRunner) { r.failMountTable(unreadable) },
			wantErr: unreadable,
		},
		// Nothing is mounted at the target at all. Absence is not an answer
		// about propagation, and reading it as one would pass the case where
		// the mount went missing entirely.
		"nothing is mounted at the target": {
			arrange: func(r *fakeRunner) { r.scriptMount("/dev/drbd0", "") },
			wantErr: mountinfo.ErrNotMounted,
		},
		// Something else is mounted over the target; the guard asks about this device.
		"another device covers the target": {
			arrange: func(r *fakeRunner) { r.overMount(testMountPoint, "/dev/other") },
			wantErr: mountinfo.ErrNotVisibleThere,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, r := mountedProvider(t, requirePropagation)
			tc.arrange(r)

			err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
			var capErr *preflight.CapabilityError
			if !errors.As(err, &capErr) {
				t.Fatalf("Mount = %v, want a preflight.CapabilityError rather than a pass", err)
			}
			if capErr.Cause != preflight.CauseIndeterminate {
				t.Errorf("Cause = %q, want %q: a guard that cannot see must not report what a passing guard reports",
					capErr.Cause, preflight.CauseIndeterminate)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Mount = %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestMountRefusesWhenTheInjectedTableCannotReportPropagation: New refuses the pairing.
func TestMountRefusesWhenTheInjectedTableCannotReportPropagation(t *testing.T) {
	settings := testSettings(t)
	requirePropagation(settings)

	_, err := New(settings,
		WithRunner(newFakeRunner(t)),
		WithMounter(&mount.Fake{}),
		WithMountTable(tableWithoutPropagation{}),
		WithBlockDevices(newFakeRunner(t)),
		WithSecretProvider(testSecretProvider),
	)
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New over a table that cannot report propagation = %v, want ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), SettingMountPropagation) {
		t.Errorf("New = %v, want the error to name %s", err, SettingMountPropagation)
	}

	// And the same table is fine with the guard off, which is what makes the
	// refusal above about the configuration rather than about the table.
	if _, err := New(testSettings(t),
		WithRunner(newFakeRunner(t)),
		WithMounter(&mount.Fake{}),
		WithMountTable(tableWithoutPropagation{}),
		WithBlockDevices(newFakeRunner(t)),
		WithSecretProvider(testSecretProvider),
	); err != nil {
		t.Fatalf("New over the same table with the guard off = %v, want nil", err)
	}
}

// tableWithoutPropagation is a MountTable with none of the optional propagation
// half — the shape a caller outside this module can legitimately build, since
// PropagationOf is deliberately not on MountTable.
type tableWithoutPropagation struct{}

func (tableWithoutPropagation) MountPointsFor(context.Context, string) ([]string, error) {
	return nil, nil
}

func (tableWithoutPropagation) VisibleMountPointsFor(context.Context, string) ([]string, error) {
	return nil, nil
}

// TestUnwindLeavesAMountThatIsNoLongerOurs: the mount ID tells a second mount of the same device apart.
func TestUnwindLeavesAMountThatIsNoLongerOurs(t *testing.T) {
	p, r, m := newTestProviderWith(t, requirePropagation)
	provision(t, p, r, defaultSpec())
	r.reset()
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")
	r.scriptMount("/dev/drbd0", testMountPoint)

	// Somebody stacks another mount of the same device on the target in the
	// instant after the guard read it.
	r.onPropagationLookup(func() { r.restack("/dev/drbd0", testMountPoint) })

	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	if !errors.Is(err, mountguard.ErrTargetTakenOver) {
		t.Fatalf("Mount = %v, want it to report that the refused mount was left in place", err)
	}
	// The finding is still there: an operator needs both facts, the reason the
	// mount was refused and what happened to the cleanup.
	var capErr *preflight.CapabilityError
	if !errors.As(err, &capErr) {
		t.Errorf("Mount = %v, want the propagation finding joined onto the unwind failure", err)
	}
	if got := m.UnmountCalls(); len(got) != 0 {
		t.Fatalf("unmount calls = %v, want none: unmounting the path would detach somebody else's mount", got)
	}
}

// TestUnwindRunsOnItsOwnContext: the rollback works with ctx already dead.
func TestUnwindRunsOnItsOwnContext(t *testing.T) {
	p, r, m := newTestProviderWith(t, requirePropagation)
	provision(t, p, r, defaultSpec())
	r.reset()
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")
	r.scriptMount("/dev/drbd0", testMountPoint)

	ctx, cancel := context.WithCancel(context.Background())
	// The mount propagates, so the only thing left to refuse it is the caller
	// giving up — canceled between mount(2) returning and the verdict.
	r.withPropagation(testMountPoint, "shared:214")
	r.onPropagationLookup(cancel)

	err := p.Mount(ctx, testVolume, testMountPoint, common.MountOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Mount with a context canceled mid-verification = %v, want it to report the cancellation", err)
	}
	if got := m.UnmountCalls(); len(got) != 1 || got[0] != testMountPoint {
		t.Fatalf("unmount calls = %v, want exactly one at %q: the rollback must not inherit the dead context", got, testMountPoint)
	}
}

// TestMountPropagationSettingRefusesAMisspelling keeps the settings path from
// turning a typo into the default, which is "off". A security guard that is
// silently absent because somebody wrote "share" is the failure this whole
// change is about.
func TestMountPropagationSettingRefusesAMisspelling(t *testing.T) {
	settings := testSettings(t)
	settings[SettingMountPropagation] = "share"

	_, err := ParseConfig(settings)
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("ParseConfig with %s=share = %v, want ErrInvalidArgument", SettingMountPropagation, err)
	}
	for _, spelling := range mountguard.Spellings() {
		if !strings.Contains(err.Error(), spelling) {
			t.Errorf("ParseConfig = %v, want the error to name the accepted value %q", err, spelling)
		}
	}
}

// TestMountPropagationSettingParses pins the two spellings and the default, so
// the settings vocabulary cannot drift from pkg/local's.
func TestMountPropagationSettingParses(t *testing.T) {
	for raw, want := range map[string]MountPropagationPolicy{
		"":          MountPropagationUnchecked,
		"unchecked": MountPropagationUnchecked,
		"shared":    MountPropagationShared,
	} {
		settings := testSettings(t)
		if raw != "" {
			settings[SettingMountPropagation] = raw
		}
		cfg, err := ParseConfig(settings)
		if err != nil {
			t.Fatalf("ParseConfig with %s=%q: %v", SettingMountPropagation, raw, err)
		}
		if cfg.MountPropagation != want {
			t.Errorf("%s=%q parsed as %v, want %v", SettingMountPropagation, raw, cfg.MountPropagation, want)
		}
	}
}
