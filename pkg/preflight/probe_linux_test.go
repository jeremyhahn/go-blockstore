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

//go:build linux

package preflight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"golang.org/x/sys/unix"
)

// -----------------------------------------------------------------------------
// classification
// -----------------------------------------------------------------------------

// TestClassifyDeviceMapperOpen covers every errno open(2) can produce on the
// control node, including the ones that must land on CauseIndeterminate.
func TestClassifyDeviceMapperOpen(t *testing.T) {
	cases := map[string]struct {
		err  error
		want Cause
	}{
		"node absent in this namespace":     {unix.ENOENT, CauseDeviceMissing},
		"the file's own permissions refuse": {unix.EACCES, CauseDeviceNotReadable},
		"driver not loaded":                 {unix.ENXIO, CauseKernelUnsupported},
		"no such device":                    {unix.ENODEV, CauseKernelUnsupported},
		"an errno with no row":              {unix.EIO, CauseIndeterminate},
		"not an errno at all":               {errors.New("something else"), CauseIndeterminate},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyDeviceMapperOpen(tc.err, func() openWitness { return openWitnessWorks })
			if got.Cause != tc.want {
				t.Errorf("Cause = %q, want %q", got.Cause, tc.want)
			}
			if got.Capability != CapabilityDeviceMapper {
				t.Errorf("Capability = %q, want %q", got.Capability, CapabilityDeviceMapper)
			}
			if !strings.Contains(got.Probe, DeviceMapperControl) {
				t.Errorf("Probe does not name the control node: %q", got.Probe)
			}
		})
	}
}

// TestClassifyDeviceMapperIoctl covers the ioctl half.
//
// EACCES and EPERM are the important rows and they mean different things: the
// device-mapper handler's own capability check answers EACCES, a seccomp filter
// denying ioctl answers EPERM before the handler runs. Collapsing them sends an
// operator to grant a capability that is already held.
func TestClassifyDeviceMapperIoctl(t *testing.T) {
	cases := map[string]struct {
		err  error
		want Cause
	}{
		"CAP_SYS_ADMIN missing":          {unix.EACCES, CausePrivilegeMissing},
		"a seccomp filter refuses ioctl": {unix.EPERM, CauseSyscallBlocked},
		"no such syscall":                {unix.ENOSYS, CauseKernelUnsupported},
		"not the control node":           {unix.ENOTTY, CauseIndeterminate},
		"an unclassified errno":          {unix.EBADF, CauseIndeterminate},
		"not an errno at all":            {errors.New("something else"), CauseIndeterminate},
		"a wrapped known errno":          {wrapped(unix.EACCES), CausePrivilegeMissing},
		"a wrapped unknown errno":        {wrapped(unix.EIO), CauseIndeterminate},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classifyDeviceMapperIoctl(tc.err).Cause; got != tc.want {
				t.Errorf("Cause = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClassifyDeviceMapperOpenEPERM is the refusal two opposite fixes produce.
//
// Codex blocked the first version of this for asserting the device cgroup
// outright: a seccomp rule can refuse the openat instead, and telling an
// operator to widen device access when the profile is the problem is a worse
// answer than saying so. The witness narrows it by opening a file this process
// created; where it cannot, the remedy names both.
func TestClassifyDeviceMapperOpenEPERM(t *testing.T) {
	cases := map[string]struct {
		witness    func() openWitness
		want       Cause
		wantDetail string
	}{
		"openat is refused outright, so it is a syscall filter": {
			func() openWitness { return openWitnessBlocked },
			CauseSyscallBlocked,
			"a syscall filter is refusing openat outright",
		},
		"openat works, so the device cgroup is the likely refusal": {
			func() openWitness { return openWitnessWorks },
			CauseDeviceAccessDenied,
			"not being refused wholesale",
		},
		"no witness, so the remedy must name both": {
			func() openWitness { return openWitnessUnknown },
			CauseDeviceAccessDenied,
			"could not be established",
		},
		"no witness function at all": {
			nil,
			CauseDeviceAccessDenied,
			"could not be established",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyDeviceMapperOpen(unix.EPERM, tc.witness)
			if got.Cause != tc.want {
				t.Fatalf("Cause = %q, want %q", got.Cause, tc.want)
			}
			if !strings.Contains(got.Probe, tc.wantDetail) {
				t.Errorf("the finding does not record what the witness established: %q", got.Probe)
			}
			// Whatever the witness said, the remedy must never assert one fix
			// when the other is possible.
			if got.Cause == CauseDeviceAccessDenied && !strings.Contains(got.Remedy(), "seccomp") {
				t.Errorf("the device-access remedy does not mention the other possible fix:\n%s", got.Remedy())
			}
			if got.Cause == CauseDeviceAccessDenied && !strings.Contains(got.Remedy(), "--device") {
				t.Errorf("the device-access remedy does not name the device fix:\n%s", got.Remedy())
			}
		})
	}
}

// TestOpenWitnessAt drives the refusals a host that can open files cannot
// produce.
func TestOpenWitnessAt(t *testing.T) {
	cases := map[string]struct {
		openErr  error
		closeErr error
		want     openWitness
	}{
		"open succeeds":                      {nil, nil, openWitnessWorks},
		"open is refused by a filter":        {unix.EPERM, nil, openWitnessBlocked},
		"open fails for an unrelated reason": {unix.ENOENT, nil, openWitnessUnknown},
		"the descriptor will not close":      {nil, unix.EBADF, openWitnessUnknown},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := openWitnessAt("/tmp/witness",
				func(string) (int, error) { return 7, tc.openErr },
				func(int) error { return tc.closeErr })
			if got != tc.want {
				t.Errorf("openWitnessAt = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLiveOpenWitness exercises the positive open test against the real kernel
// and checks it leaves nothing behind.
func TestLiveOpenWitness(t *testing.T) {
	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading %s: %v", os.TempDir(), err)
	}

	got := liveOpenWitness()
	// This process demonstrably opened files to get here, so a wholesale filter
	// is not in force and the answer cannot be "blocked".
	if got == openWitnessBlocked {
		t.Fatalf("liveOpenWitness = blocked in a process that is reading files")
	}
	if got != openWitnessWorks {
		t.Errorf("liveOpenWitness = %v, want openWitnessWorks", got)
	}

	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading %s: %v", os.TempDir(), err)
	}
	if len(after) != len(before) {
		t.Errorf("the witness left %d entries behind in %s", len(after)-len(before), os.TempDir())
	}
}

// TestClassifyMount is the three-way split the remount probe exists to produce.
//
// EINVAL is the PASS — the request reached the kernel's own validation, which
// means it got past the security modules and the capability check. Reading it
// as a failure would make the guard refuse every correctly configured host.
func TestClassifyMount(t *testing.T) {
	witnessing := func(concluded capabilityWitness) func() capabilityWitness {
		return func() capabilityWitness { return concluded }
	}

	cases := map[string]struct {
		err      error
		witness  func() capabilityWitness
		wantPass bool
		want     Cause
	}{
		"rejected on its merits, so mount is permitted": {unix.EINVAL, witnessing(witnessHeld), true, ""},
		"outright success, which cannot occur":          {nil, witnessing(witnessHeld), true, ""},
		"a security module":                             {unix.EACCES, witnessing(witnessHeld), false, CauseLSMDenied},
		"the directory vanished":                        {unix.ENOENT, witnessing(witnessHeld), false, CauseIndeterminate},
		"not an errno at all":                           {errors.New("x"), witnessing(witnessHeld), false, CauseIndeterminate},

		// EPERM is the answer two independent mechanisms produce, so the
		// witness — not the errno — decides which remedy an operator is given.
		"EPERM with the capability demonstrably held is seccomp": {
			unix.EPERM, witnessing(witnessHeld), false, CauseSyscallBlocked,
		},
		"EPERM with the capability demonstrably absent is the capability": {
			unix.EPERM, witnessing(witnessNotHeld), false, CausePrivilegeMissing,
		},
		"EPERM with no witness is reported as ambiguous rather than guessed": {
			unix.EPERM, witnessing(witnessUnknown), false, CausePrivilegeOrPolicy,
		},
		"EPERM with no witness at all is ambiguous, not a pass": {
			unix.EPERM, nil, false, CausePrivilegeOrPolicy,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyMount(tc.err, tc.witness)
			if tc.wantPass {
				if got != nil {
					t.Fatalf("classifyMount(%v) = %v, want a pass", tc.err, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("classifyMount(%v) reported a pass", tc.err)
			}
			if got.Cause != tc.want {
				t.Errorf("Cause = %q, want %q", got.Cause, tc.want)
			}
		})
	}
}

// TestClassifyMountRemedyMatchesTheWitness is the point of the witness: the
// operator must be told to fix the mechanism that is actually broken.
//
// Codex found this on review of the first draft — every EPERM was reported as a
// missing capability, so a container that HELD CAP_SYS_ADMIN and had mount(2)
// denied by seccomp was told to grant a capability it already had.
func TestClassifyMountRemedyMatchesTheWitness(t *testing.T) {
	held := classifyMount(unix.EPERM, func() capabilityWitness { return witnessHeld })
	if strings.Contains(held.Remedy(), "--cap-add SYS_ADMIN") {
		t.Errorf("a seccomp denial was answered with a capability grant:\n%s", held.Remedy())
	}
	if !strings.Contains(held.Remedy(), "seccomp") {
		t.Errorf("a seccomp denial was not answered with a seccomp change:\n%s", held.Remedy())
	}

	absent := classifyMount(unix.EPERM, func() capabilityWitness { return witnessNotHeld })
	if !strings.Contains(absent.Remedy(), "--cap-add SYS_ADMIN") {
		t.Errorf("a missing capability was not answered with a capability grant:\n%s", absent.Remedy())
	}

	ambiguous := classifyMount(unix.EPERM, func() capabilityWitness { return witnessUnknown })
	remedy := ambiguous.Remedy()
	if !strings.Contains(remedy, "--cap-add SYS_ADMIN") || !strings.Contains(remedy, "seccomp") {
		t.Errorf("an unresolved EPERM did not name both mechanisms:\n%s", remedy)
	}
	if !strings.Contains(ambiguous.Probe, "could not be witnessed") {
		t.Errorf("the finding does not say the witness was unavailable: %q", ambiguous.Probe)
	}
}

// TestDeviceMapperWitness covers the positive capability test, including every
// answer that must NOT be read as "the capability is missing".
//
// The EACCES/EPERM split is the second finding Codex raised, and it is measured
// rather than argued: with the control node passed into a container as uid 0,
// removing CAP_SYS_ADMIN produces EACCES from the kernel's own check, while
// removing ioctl from the seccomp profile produces EPERM before that check runs.
// Treating EPERM as a missing capability would tell an operator who HOLDS
// CAP_SYS_ADMIN to grant it.
func TestDeviceMapperWitness(t *testing.T) {
	cases := map[string]struct {
		openErr    error
		versionErr error
		closeErr   error
		want       capabilityWitness
	}{
		"the ioctl succeeds, so the kernel confirms the capability":       {nil, nil, nil, witnessHeld},
		"an unclean probe is not evidence of a capability":                {nil, nil, unix.EBADF, witnessUnknown},
		"EACCES is the kernel's own capability check, so it disproves it": {nil, unix.EACCES, nil, witnessNotHeld},
		"EPERM is a seccomp filter, which proves nothing either way":      {nil, unix.EPERM, nil, witnessUnknown},
		"the control node is absent, which says nothing":                  {unix.ENOENT, nil, nil, witnessUnknown},
		"the control node cannot be opened, which says nothing":           {unix.EACCES, nil, nil, witnessUnknown},
		"the ioctl fails for an unrelated reason":                         {nil, unix.ENOTTY, nil, witnessUnknown},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			closed := 0
			got := deviceMapperWitness(deviceMapperSteps{
				open:    func(string) (int, error) { return 7, tc.openErr },
				version: func(int) error { return tc.versionErr },
				close:   func(int) error { closed++; return tc.closeErr },
			})
			if got != tc.want {
				t.Errorf("deviceMapperWitness = %v, want %v", got, tc.want)
			}
			if tc.openErr == nil && closed != 1 {
				t.Errorf("the witness closed the descriptor %d times, want 1", closed)
			}
			if tc.openErr != nil && closed != 0 {
				t.Error("the witness closed a descriptor it never opened")
			}
		})
	}
}

// TestClassifyKeyring maps go-luks2's sentinels onto this package's causes and
// keeps an unrecognized keyring condition from being guessed at.
func TestClassifyKeyring(t *testing.T) {
	cases := map[string]struct {
		err      error
		wantPass bool
		want     Cause
	}{
		"available":                   {nil, true, ""},
		"seccomp":                     {luks2.ErrKeyringBlocked, false, CauseSyscallBlocked},
		"kernel without CONFIG_KEYS":  {luks2.ErrKeyringUnsupported, false, CauseKernelUnsupported},
		"quota":                       {luks2.ErrKeyringQuotaExhausted, false, CauseResourceExhausted},
		"an anomaly go-luks2 reports": {luks2.ErrKeyringKeyNotReleased, false, CauseIndeterminate},
		"something else entirely":     {errors.New("unrelated"), false, CauseIndeterminate},
		"a wrapped sentinel":          {wrapped(luks2.ErrKeyringBlocked), false, CauseSyscallBlocked},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyKeyring(tc.err)
			if tc.wantPass {
				if got != nil {
					t.Fatalf("classifyKeyring(nil) = %v, want a pass", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("classifyKeyring(%v) reported a pass", tc.err)
			}
			if got.Cause != tc.want {
				t.Errorf("Cause = %q, want %q", got.Cause, tc.want)
			}
			if got.Capability != CapabilityKernelKeyring {
				t.Errorf("Capability = %q, want %q", got.Capability, CapabilityKernelKeyring)
			}
		})
	}
}

// wrapped hides an error one layer down, the way a real call stack does.
func wrapped(err error) error { return &wrapper{err} }

type wrapper struct{ err error }

func (w *wrapper) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrapper) Unwrap() error { return w.err }

// -----------------------------------------------------------------------------
// the probes, driven through their seams
// -----------------------------------------------------------------------------

// TestDeviceMapperProbeWithInjectedSteps drives every branch of the probe,
// including the ones no single host can produce.
func TestDeviceMapperProbeWithInjectedSteps(t *testing.T) {
	t.Run("everything works", func(t *testing.T) {
		closed := 0
		probe := deviceMapperProbe(deviceMapperSteps{
			open:    func(string) (int, error) { return 7, nil },
			version: func(fd int) error { return nil },
			close:   func(int) error { closed++; return nil },
		})
		if err := probe(context.Background()); err != nil {
			t.Fatalf("probe: %v", err)
		}
		if closed != 1 {
			t.Errorf("the descriptor was closed %d times, want 1", closed)
		}
	})

	t.Run("the node is visible but not usable", func(t *testing.T) {
		// The device-cgroup case: the container can SEE /dev/mapper/control and
		// may not use it. Measured — bind-mounting the node instead of passing
		// it with --device produces exactly this, and it is the one refusal
		// where granting a capability is guaranteed not to help.
		probe := deviceMapperProbe(deviceMapperSteps{
			open:      func(string) (int, error) { return -1, unix.EPERM },
			version:   func(int) error { t.Fatal("the ioctl ran after the open failed"); return nil },
			close:     func(int) error { t.Fatal("a descriptor was closed that was never opened"); return nil },
			openWorks: func() openWitness { return openWitnessWorks },
		})
		err := probe(context.Background())
		if !errors.Is(err, ErrDeviceAccessDenied) {
			t.Fatalf("probe = %v, want ErrDeviceAccessDenied", err)
		}
		if !strings.Contains(err.Error(), "--device /dev/mapper/control") {
			t.Errorf("the refusal does not name the fix: %v", err)
		}
		if strings.Contains(err.Error(), "Allow the syscall") {
			t.Errorf("a device-cgroup denial was answered with a seccomp change: %v", err)
		}
	})

	t.Run("the node cannot be opened", func(t *testing.T) {
		closed := 0
		probe := deviceMapperProbe(deviceMapperSteps{
			open:    func(string) (int, error) { return -1, unix.ENOENT },
			version: func(int) error { t.Fatal("the ioctl ran after the open failed"); return nil },
			close:   func(int) error { closed++; return nil },
		})
		if err := probe(context.Background()); !errors.Is(err, ErrDeviceMissing) {
			t.Fatalf("probe = %v, want ErrDeviceMissing", err)
		}
		if closed != 0 {
			t.Error("a descriptor was closed that was never opened")
		}
	})

	t.Run("the ioctl is denied", func(t *testing.T) {
		closed := 0
		probe := deviceMapperProbe(deviceMapperSteps{
			open:    func(string) (int, error) { return 7, nil },
			version: func(int) error { return unix.EACCES },
			close:   func(int) error { closed++; return nil },
		})
		err := probe(context.Background())
		if !errors.Is(err, ErrPrivilegeMissing) {
			t.Fatalf("probe = %v, want ErrPrivilegeMissing", err)
		}
		if closed != 1 {
			t.Errorf("the descriptor was closed %d times after a denied ioctl, want 1", closed)
		}
	})

	t.Run("the descriptor cannot be closed", func(t *testing.T) {
		probe := deviceMapperProbe(deviceMapperSteps{
			open:    func(string) (int, error) { return 7, nil },
			version: func(int) error { return nil },
			close:   func(int) error { return unix.EBADF },
		})
		if err := probe(context.Background()); !errors.Is(err, ErrIndeterminate) {
			t.Fatalf("probe = %v, want ErrIndeterminate: a probe that cannot account for what it opened is not evidence", err)
		}
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := deviceMapperProbe(deviceMapperSteps{
			open: func(string) (int, error) { t.Fatal("the probe ran with a canceled context"); return 0, nil },
		})
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestMountProbeWithInjectedSteps drives every branch, and checks the throwaway
// directory is removed on every one of them.
func TestMountProbeWithInjectedSteps(t *testing.T) {
	cases := map[string]struct {
		remount  error
		wantPass bool
		wantIs   error
	}{
		"permitted":           {unix.EINVAL, true, nil},
		"capability missing":  {unix.EPERM, false, ErrPrivilegeMissing},
		"security module":     {unix.EACCES, false, ErrLSMDenied},
		"an unexpected errno": {unix.EIO, false, ErrIndeterminate},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			removed := ""
			probe := mountProbe(mountSteps{
				tempDir: func() (string, error) { return "/tmp/probe-target", nil },
				remount: func(string) error { return tc.remount },
				remove:  func(path string) error { removed = path; return nil },
				witness: func() capabilityWitness { return witnessNotHeld },
			})

			err := probe(context.Background())
			if tc.wantPass && err != nil {
				t.Fatalf("probe = %v, want a pass", err)
			}
			if !tc.wantPass && !errors.Is(err, tc.wantIs) {
				t.Fatalf("probe = %v, want %v", err, tc.wantIs)
			}
			if removed != "/tmp/probe-target" {
				t.Errorf("the throwaway directory was not removed (removed %q)", removed)
			}
		})
	}

	t.Run("the throwaway directory cannot be created", func(t *testing.T) {
		probe := mountProbe(mountSteps{
			tempDir: func() (string, error) { return "", unix.EROFS },
			remount: func(string) error { t.Fatal("the remount ran without a target"); return nil },
			remove:  func(string) error { t.Fatal("something was removed that was never created"); return nil },
		})
		if err := probe(context.Background()); !errors.Is(err, ErrIndeterminate) {
			t.Fatalf("probe = %v, want ErrIndeterminate", err)
		}
	})

	t.Run("the throwaway directory cannot be removed", func(t *testing.T) {
		probe := mountProbe(mountSteps{
			tempDir: func() (string, error) { return "/tmp/probe-target", nil },
			remount: func(string) error { return unix.EINVAL },
			remove:  func(string) error { return unix.EBUSY },
		})
		err := probe(context.Background())
		if !errors.Is(err, ErrIndeterminate) {
			t.Fatalf("probe = %v, want ErrIndeterminate: an artifact this probe left behind turns a pass into an unfinished check", err)
		}
		if !strings.Contains(err.Error(), "/tmp/probe-target") {
			t.Errorf("the failure does not name the artifact left behind: %v", err)
		}
	})

	t.Run("a refusal outranks a failed cleanup", func(t *testing.T) {
		probe := mountProbe(mountSteps{
			tempDir: func() (string, error) { return "/tmp/probe-target", nil },
			remount: func(string) error { return unix.EPERM },
			remove:  func(string) error { return unix.EBUSY },
			witness: func() capabilityWitness { return witnessNotHeld },
		})
		if err := probe(context.Background()); !errors.Is(err, ErrPrivilegeMissing) {
			t.Fatalf("probe = %v, want the capability refusal rather than the cleanup failure", err)
		}
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := mountProbe(mountSteps{
			tempDir: func() (string, error) { t.Fatal("the probe ran with a canceled context"); return "", nil },
		})
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestKeyringProbeWithAnInjectedCheck drives the delegation, including the
// interface trap that made a passing check panic.
func TestKeyringProbeWithAnInjectedCheck(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		if err := keyringProbe(func() error { return nil })(context.Background()); err != nil {
			t.Fatalf("probe = %v, want a pass", err)
		}
	})

	t.Run("a pass is a true nil, not a typed one", func(t *testing.T) {
		// The regression: returning classifyKeyring's *CapabilityError directly
		// boxes a nil pointer in a non-nil error, which panics when rendered.
		err := keyringProbe(func() error { return nil })(context.Background())
		if err != nil {
			t.Fatalf("probe = %v (%T), want an untyped nil", err, err)
		}
	})

	t.Run("blocked by seccomp", func(t *testing.T) {
		err := keyringProbe(func() error { return luks2.ErrKeyringBlocked })(context.Background())
		if !errors.Is(err, ErrSyscallBlocked) {
			t.Fatalf("probe = %v, want ErrSyscallBlocked", err)
		}
		if !strings.Contains(err.Error(), "seccomp") {
			t.Errorf("the refusal does not mention seccomp, which is the remedy: %v", err)
		}
		// Asserted HERE as well as in the live test, because the live test can
		// only reach this branch on a host where the keyring is actually
		// blocked — and a property that is only checked on some machines is a
		// property that goes red in CI and green on a desk.
		requireNamesTheStorageComponent(t, err)
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := keyringProbe(func() error { t.Fatal("the check ran with a canceled context"); return nil })
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestDeviceMapperVersionOnADescriptorThatIsNotTheControlNode exercises the
// real ioctl against a descriptor this test owns.
//
// It is how the syscall itself gets covered on a machine where the control node
// cannot be opened: the dm_ioctl header is populated and the ioctl is issued for
// real, and a regular file answers ENOTTY — "this descriptor does not take this
// ioctl" — which is exactly the answer that must NOT be read as a capability
// problem. The path where the ioctl succeeds needs the control node and is
// covered by scripts/preflight-container-matrix.sh.
func TestDeviceMapperVersionOnADescriptorThatIsNotTheControlNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-device")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening a file this test just created: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	err = deviceMapperVersion(fd)
	if err == nil {
		t.Fatal("a regular file answered the device-mapper version ioctl")
	}
	if !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("deviceMapperVersion = %v, want ENOTTY", err)
	}
	if got := classifyDeviceMapperIoctl(err).Cause; got != CauseIndeterminate {
		t.Errorf("Cause = %q, want %q: a descriptor that is not the control node is not a privilege problem", got, CauseIndeterminate)
	}
}

// -----------------------------------------------------------------------------
// the live probes, against this kernel
// -----------------------------------------------------------------------------

// environment is what an INDEPENDENT measurement says this process can do.
//
// It is the oracle the live probes are judged against. Reading capability bits
// is exactly what a guard must not do — but it is exactly what a test SHOULD do
// to check the guard, because it is a second, unrelated source of truth for the
// same fact. The probes attempt the operation; the oracle reads /proc; they have
// to agree.
type environment struct {
	hasCapSysAdmin   bool
	inUserNamespace  bool
	dmControlOpenErr error
	keyringErr       error
}

// capSysAdmin is bit 21 of the capability bitmask.
const capSysAdmin = 21

func measureEnvironment(t *testing.T) environment {
	t.Helper()

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("reading /proc/self/status, which this test needs as its oracle: %v", err)
	}
	var effective uint64
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		effective, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			t.Fatalf("parsing CapEff from /proc/self/status: %v", err)
		}
	}

	// A user namespace makes CapEff a statement about THAT namespace, while the
	// kernel checks device-mapper and mount against the initial one. The
	// identity map is what says there is no such indirection.
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatalf("reading /proc/self/uid_map: %v", err)
	}
	inUserNS := strings.Join(strings.Fields(string(uidMap)), " ") != "0 0 4294967295"

	env := environment{
		hasCapSysAdmin:  effective&(1<<capSysAdmin) != 0,
		inUserNamespace: inUserNS,
		keyringErr:      luks2.CheckKeyringAvailable(),
	}

	fd, openErr := unix.Open(DeviceMapperControl, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if openErr == nil {
		_ = unix.Close(fd)
	}
	env.dmControlOpenErr = openErr

	t.Logf("environment: CAP_SYS_ADMIN=%v userns=%v %s open=%v keyring=%v",
		env.hasCapSysAdmin, env.inUserNamespace, DeviceMapperControl, env.dmControlOpenErr, env.keyringErr)
	return env
}

// TestLiveDeviceMapperProbeAgreesWithTheEnvironment is the two-sided test on a
// real kernel: the probe must refuse where an independent measurement says the
// operation cannot work, and must NOT refuse where it says it can.
//
// The second half is the one that matters. A guard that refuses everything
// passes every test that only checks refusals.
func TestLiveDeviceMapperProbeAgreesWithTheEnvironment(t *testing.T) {
	env := measureEnvironment(t)
	err := deviceMapperProbe(liveDeviceMapperSteps())(context.Background())

	switch {
	case errors.Is(env.dmControlOpenErr, unix.ENOENT):
		if !errors.Is(err, ErrDeviceMissing) {
			t.Fatalf("the control node does not exist and the probe said %v, want ErrDeviceMissing", err)
		}
	case errors.Is(env.dmControlOpenErr, unix.EACCES):
		// The node's own permissions. Not a capability, and not a policy: a
		// process that is not uid 0 and holds no CAP_DAC_OVERRIDE is refused
		// here before the kernel consults anything else.
		if !errors.Is(err, ErrDeviceNotReadable) {
			t.Fatalf("the control node refused the open with EACCES and the probe said %v, want ErrDeviceNotReadable", err)
		}
		if strings.Contains(err.Error(), "--cap-add SYS_ADMIN") {
			t.Errorf("a file-permission denial was answered with a capability grant: %v", err)
		}
	case errors.Is(env.dmControlOpenErr, unix.EPERM):
		if !errors.Is(err, ErrDeviceAccessDenied) {
			t.Fatalf("the control node refused the open with EPERM and the probe said %v, want ErrDeviceAccessDenied", err)
		}
	case env.dmControlOpenErr != nil:
		if err == nil {
			t.Fatalf("the control node could not be opened (%v) and the probe passed", env.dmControlOpenErr)
		}
	case !env.hasCapSysAdmin:
		// The node opens, so the refusal has to come from the ioctl.
		if !errors.Is(err, ErrPrivilegeMissing) {
			t.Fatalf("CAP_SYS_ADMIN is absent and the probe said %v, want ErrPrivilegeMissing", err)
		}
	case env.inUserNamespace:
		// CapEff describes a namespace the device-mapper ioctl does not consult,
		// so either answer is consistent; all that is required is that it is a
		// classified one.
		requireClassified(t, err)
	default:
		if err != nil {
			t.Fatalf("the control node opens and CAP_SYS_ADMIN is held, so device-mapper works here, but the probe refused: %v", err)
		}
	}
}

// TestLiveMountProbeAgreesWithTheEnvironment is the same two-sided check for
// mount(2), with the third mechanism included: a security module can deny it
// even where the capability is held, which was measured on Docker's default
// AppArmor profile.
func TestLiveMountProbeAgreesWithTheEnvironment(t *testing.T) {
	env := measureEnvironment(t)
	err := mountProbe(liveMountSteps())(context.Background())

	switch {
	case !env.hasCapSysAdmin && env.dmControlOpenErr == nil:
		// The capability is absent AND the witness is available, so the probe
		// has everything it needs to name the capability specifically.
		if !errors.Is(err, ErrPrivilegeMissing) {
			t.Fatalf("CAP_SYS_ADMIN is absent and witnessable, and the mount probe said %v, want ErrPrivilegeMissing", err)
		}
	case !env.hasCapSysAdmin:
		// The capability is absent and the control node is out of reach, so
		// EPERM cannot be attributed. The probe must refuse and say so — and
		// must NOT claim the capability is held.
		if err == nil {
			t.Fatal("CAP_SYS_ADMIN is absent and the mount probe passed")
		}
		if errors.Is(err, ErrSyscallBlocked) {
			t.Fatalf("the probe claimed the capability is held with no witness for it: %v", err)
		}
		if !errors.Is(err, ErrPrivilegeOrPolicy) && !errors.Is(err, ErrPrivilegeMissing) && !errors.Is(err, ErrLSMDenied) {
			t.Fatalf("the mount probe said %v, want the capability, the ambiguity, or an LSM denial", err)
		}
	case env.inUserNamespace:
		requireClassified(t, err)
	default:
		// The capability is held in the initial namespace. mount(2) is then
		// permitted, or denied by a security module, or denied by a seccomp
		// filter — never reported as a MISSING capability, which is the
		// misclassification the witness exists to prevent.
		if errors.Is(err, ErrPrivilegeMissing) {
			t.Fatalf("CAP_SYS_ADMIN is held and the probe reported it missing: %v", err)
		}
		if err != nil && !errors.Is(err, ErrLSMDenied) && !errors.Is(err, ErrSyscallBlocked) {
			t.Fatalf("CAP_SYS_ADMIN is held and the mount probe said %v; the legitimate refusals here are an LSM denial or a seccomp denial", err)
		}
	}
}

// TestLiveDeviceMapperWitnessAgreesWithTheEnvironment checks the positive
// capability test itself against an independent reading, in both directions.
func TestLiveDeviceMapperWitnessAgreesWithTheEnvironment(t *testing.T) {
	env := measureEnvironment(t)
	got := deviceMapperWitness(liveDeviceMapperSteps())

	switch {
	case env.dmControlOpenErr != nil:
		if got != witnessUnknown {
			t.Fatalf("the control node could not be opened (%v) and the witness concluded %v; neither absence nor a permission denial on the NODE says anything about CAP_SYS_ADMIN", env.dmControlOpenErr, got)
		}
	case env.hasCapSysAdmin && !env.inUserNamespace:
		if got != witnessHeld {
			t.Fatalf("CAP_SYS_ADMIN is held and the node opens, and the witness concluded %v, want witnessHeld", got)
		}
	case !env.hasCapSysAdmin:
		if got == witnessHeld {
			t.Fatalf("CAP_SYS_ADMIN is absent and the witness concluded it is held")
		}
	}
}

// TestLiveKeyringProbeAgreesWithGoLuks2 checks the delegation is faithful: this
// package must reach exactly the same verdict as the library that owns the
// keyring, on whatever machine the test runs.
func TestLiveKeyringProbeAgreesWithGoLuks2(t *testing.T) {
	env := measureEnvironment(t)
	err := keyringProbe(luks2.CheckKeyringAvailable)(context.Background())

	if (env.keyringErr == nil) != (err == nil) {
		t.Fatalf("go-luks2 says %v and the probe says %v; the verdicts must match", env.keyringErr, err)
	}
	if err == nil {
		return
	}
	requireClassified(t, err)
	requireNamesTheStorageComponent(t, err)
}

// requireNamesTheStorageComponent checks the refusal says WHOSE requirement this
// is, which is the whole point of the privilege-separated deployment: the
// workload container needs none of it.
//
// The comparison is case-insensitive on purpose. The first version of this was
// a case-sensitive Contains for "storage component" against a remedy that says
// "STORAGE component" for emphasis — so it asserted the message's typography
// rather than its content, and it could only fail where the keyring is actually
// blocked, which this developer's host cannot produce. It went green locally and
// red in CI. The property is worth asserting; the casing is not.
func requireNamesTheStorageComponent(t *testing.T, err error) {
	t.Helper()
	if !strings.Contains(strings.ToLower(err.Error()), "storage component") {
		t.Errorf("the refusal does not say which component the requirement belongs to: %v", err)
	}
}

// TestLiveProbesLeaveNothingBehind is the cleanup requirement, measured rather
// than asserted: a probe that leaves a key, a mapping or a directory behind is
// a bug, and this repository has already been bitten by test code that damaged
// host state.
func TestLiveProbesLeaveNothingBehind(t *testing.T) {
	tempEntries := func() []string {
		entries, err := os.ReadDir(os.TempDir())
		if err != nil {
			t.Fatalf("reading %s: %v", os.TempDir(), err)
		}
		var ours []string
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "go-blockstore-preflight-") {
				ours = append(ours, filepath.Join(os.TempDir(), entry.Name()))
			}
		}
		return ours
	}

	// luksKeys counts LIVE keyring entries this stack could have created.
	//
	// The distinction between live and revoked is the whole measurement, and it
	// was found by making it. /proc/keys keeps showing a revoked key as a
	// tombstone — flags "IR-Q---", state "expd" — until the kernel's key
	// garbage collector runs on its own timer, so a naive count reports a leak
	// after every successful probe. Revoking a logon key frees its payload
	// immediately (the kernel runs the key type's revoke method there, which
	// releases the bytes), so a tombstone holds no key material and the entry
	// is already unresolvable: go-luks2 confirms that by searching for it. What
	// would be a real leak is an entry WITHOUT the revoked flag, which is what
	// this counts.
	//
	// Where /proc/keys cannot be read the count is zero on both sides, so the
	// comparison stays honest rather than turning into a hidden pass.
	luksKeys := func() int {
		raw, err := os.ReadFile("/proc/keys")
		if err != nil {
			return 0
		}
		count := 0
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 9 || fields[7] != "logon" || !strings.HasPrefix(fields[8], "luks2:") {
				continue
			}
			// R revoked, D dead, i invalidated — all of them past tense.
			if strings.ContainsAny(fields[1], "RDi") {
				continue
			}
			count++
		}
		return count
	}

	beforeDirs, beforeKeys := len(tempEntries()), luksKeys()

	for _, probe := range []Probe{
		deviceMapperProbe(liveDeviceMapperSteps()),
		mountProbe(liveMountSteps()),
		keyringProbe(luks2.CheckKeyringAvailable),
	} {
		_ = probe(context.Background())
	}

	if leftovers := tempEntries(); len(leftovers) != beforeDirs {
		t.Errorf("the probes left %d throwaway directories behind: %v", len(leftovers)-beforeDirs, leftovers)
	}
	if after := luksKeys(); after != beforeKeys {
		t.Errorf("the probes left %d live keys in the kernel keyring", after-beforeKeys)
	}
}

// TestLiveProbesAreDeterministic checks running the guard twice reaches the same
// verdict. A check whose answer moves between runs cannot be the thing a
// deployment is gated on.
func TestLiveProbesAreDeterministic(t *testing.T) {
	for _, capability := range New().Capabilities() {
		t.Run(string(capability), func(t *testing.T) {
			first := Check(context.Background(), capability)
			second := Check(context.Background(), capability)

			if (first == nil) != (second == nil) {
				t.Fatalf("two runs disagreed: %v then %v", first, second)
			}
			if first != nil && first.Error() != second.Error() {
				t.Errorf("two runs produced different messages:\n%v\n%v", first, second)
			}
		})
	}
}

// requireClassified is the fail-closed invariant that holds in every
// environment: a refusal is always a *CapabilityError with a cause that has a
// remedy, never a bare error.
func requireClassified(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var typed *CapabilityError
	if !errors.As(err, &typed) {
		t.Fatalf("the probe returned %T (%v); every refusal must be a *CapabilityError", err, err)
	}
	if typed.Cause == "" {
		t.Error("the refusal carries no cause, so it has no remedy")
	}
	if typed.Probe == "" {
		t.Error("the refusal does not say what was probed")
	}
	if typed.Remedy() == "" {
		t.Error("the refusal carries no remedy")
	}
}
