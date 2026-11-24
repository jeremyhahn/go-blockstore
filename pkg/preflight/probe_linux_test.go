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

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
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

// TestClassifyDeviceMapperIoctl: EACCES is the handler's capability check, EPERM a seccomp denial.
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

// TestClassifyDeviceMapperOpenEPERM: the witness distinguishes device cgroup from seccomp, naming both when it cannot.
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

// TestLiveOpenWitness runs the open witness on the real kernel and checks its own directories are left empty.
func TestLiveOpenWitness(t *testing.T) {
	// The witness names its directories with a fixed prefix, so its own leavings
	// are identifiable without counting anything else in the directory.
	const prefix = "go-blockstore-preflight-open-"
	witnessDirs := func() []string {
		t.Helper()
		entries, err := os.ReadDir(os.TempDir())
		if err != nil {
			t.Fatalf("reading %s: %v", os.TempDir(), err)
		}
		var mine []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), prefix) {
				mine = append(mine, e.Name())
			}
		}
		return mine
	}

	before := witnessDirs()

	got := liveOpenWitness()
	// This process demonstrably opened files to get here, so a wholesale filter
	// is not in force and the answer cannot be "blocked".
	if got == openWitnessBlocked {
		t.Fatalf("liveOpenWitness = blocked in a process that is reading files")
	}
	if got != openWitnessWorks {
		t.Errorf("liveOpenWitness = %v, want openWitnessWorks", got)
	}

	after := witnessDirs()
	if len(after) != len(before) {
		t.Errorf("the witness left %v behind in %s, up from %v", after, os.TempDir(), before)
	}
}

// TestClassifyMount: EINVAL from the remount probe is the pass.
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

// TestClassifyMountRemedyMatchesTheWitness: a held CAP_SYS_ADMIN with mount denied gets the seccomp remedy.
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

// TestDeviceMapperWitness covers the witness, including the answers that must not read as a missing capability.
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
		"seccomp":                     {dmcrypt.ErrKeyringBlocked, false, CauseSyscallBlocked},
		"kernel without CONFIG_KEYS":  {dmcrypt.ErrKeyringUnsupported, false, CauseKernelUnsupported},
		"quota":                       {dmcrypt.ErrKeyringQuotaExhausted, false, CauseResourceExhausted},
		"an anomaly go-luks2 reports": {dmcrypt.ErrKeyringKeyNotReleased, false, CauseIndeterminate},
		"something else entirely":     {errors.New("unrelated"), false, CauseIndeterminate},
		"a wrapped sentinel":          {wrapped(dmcrypt.ErrKeyringBlocked), false, CauseSyscallBlocked},
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
		if err := keyringProbe(func(context.Context) error { return nil })(context.Background()); err != nil {
			t.Fatalf("probe = %v, want a pass", err)
		}
	})

	t.Run("a pass is a true nil, not a typed one", func(t *testing.T) {
		// The regression: returning classifyKeyring's *CapabilityError directly
		// boxes a nil pointer in a non-nil error, which panics when rendered.
		err := keyringProbe(func(context.Context) error { return nil })(context.Background())
		if err != nil {
			t.Fatalf("probe = %v (%T), want an untyped nil", err, err)
		}
	})

	t.Run("blocked by seccomp", func(t *testing.T) {
		err := keyringProbe(func(context.Context) error { return dmcrypt.ErrKeyringBlocked })(context.Background())
		if !errors.Is(err, ErrSyscallBlocked) {
			t.Fatalf("probe = %v, want ErrSyscallBlocked", err)
		}
		if !strings.Contains(err.Error(), "seccomp") {
			t.Errorf("the refusal does not mention seccomp, which is the remedy: %v", err)
		}
		// Asserted here too, since the live test reaches this branch only where the keyring is blocked.
		requireNamesTheStorageComponent(t, err)
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := keyringProbe(func(context.Context) error { t.Fatal("the check ran with a canceled context"); return nil })
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestDeviceMapperVersionOnADescriptorThatIsNotTheControlNode issues the real ioctl on a regular file and expects ENOTTY.
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

// environment is an independent /proc-based measurement the live probes are checked against.
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

	// Under a user namespace CapEff does not describe the initial namespace; require the identity map.
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatalf("reading /proc/self/uid_map: %v", err)
	}
	inUserNS := strings.Join(strings.Fields(string(uidMap)), " ") != "0 0 4294967295"

	env := environment{
		hasCapSysAdmin:  effective&(1<<capSysAdmin) != 0,
		inUserNamespace: inUserNS,
		keyringErr:      dmcrypt.CheckKeyring(context.Background()),
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

// TestLiveDeviceMapperProbeAgreesWithTheEnvironment: the probe refuses exactly where the environment says it cannot work.
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
		// With the capability held, mount(2) is never reported as a missing capability.
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
	err := keyringProbe(dmcrypt.CheckKeyring)(context.Background())

	if (env.keyringErr == nil) != (err == nil) {
		t.Fatalf("go-luks2 says %v and the probe says %v; the verdicts must match", env.keyringErr, err)
	}
	if err == nil {
		return
	}
	requireClassified(t, err)
	requireNamesTheStorageComponent(t, err)
}

// requireNamesTheStorageComponent checks, case-insensitively, that the refusal names the storage component.
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

	// luksKeys counts live keyring entries this stack could create, ignoring revoked tombstones; zero where /proc/keys is unreadable.
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
		keyringProbe(dmcrypt.CheckKeyring),
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

// -----------------------------------------------------------------------------
// CAP_NET_ADMIN and the DRBD control interface
// -----------------------------------------------------------------------------

// TestTheNewProbesReturnATrueNilOnSuccess: probes return an untyped nil on success.
func TestTheNewProbesReturnATrueNilOnSuccess(t *testing.T) {
	netAdmin := netAdminProbe(netAdminSteps{
		privileged: func(string) error { return unix.EOPNOTSUPP },
		witness:    func(string) error { return unix.EOPNOTSUPP },
	})
	if err := netAdmin(context.Background()); err != nil {
		t.Errorf("the net-admin probe returned %v (%T) on success, want an untyped nil", err, err)
	}

	drbd := drbdControlProbe(drbdControlSteps{family: func(string) error { return nil }})
	if err := drbd(context.Background()); err != nil {
		t.Errorf("the drbd-control probe returned %v (%T) on success, want an untyped nil", err, err)
	}
}

// TestClassifyNetAdmin: EPERM is decided by whether the unprivileged ethtool read got through.
func TestClassifyNetAdmin(t *testing.T) {
	answering := func(err error) func() error { return func() error { return err } }

	cases := map[string]struct {
		err      error
		witness  func() error
		wantPass bool
		want     Cause
	}{
		"the driver was reached, so the capability is held": {
			unix.EOPNOTSUPP, answering(unix.EOPNOTSUPP), true, "",
		},
		"an outright success is also the capability being held": {
			nil, answering(unix.EOPNOTSUPP), true, "",
		},
		"refused, and the unprivileged read got through": {
			unix.EPERM, answering(unix.EOPNOTSUPP), false, CausePrivilegeMissing,
		},
		"refused, and the unprivileged read got through with nil": {
			unix.EPERM, answering(nil), false, CausePrivilegeMissing,
		},
		"refused, and the unprivileged read was refused too": {
			unix.EPERM, answering(unix.EPERM), false, CauseSyscallBlocked,
		},
		"refused, and the socket could not even be created": {
			unix.EPERM, answering(errors.New("socket: operation not permitted")), false, CauseSyscallBlocked,
		},
		"refused, with no witness to attribute it": {
			unix.EPERM, nil, false, CausePrivilegeOrPolicy,
		},
		"an errno neither case explains": {
			unix.EIO, answering(unix.EOPNOTSUPP), false, CauseIndeterminate,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyNetAdmin(tc.err, tc.witness)
			if tc.wantPass {
				if got != nil {
					t.Fatalf("classifyNetAdmin(%v) = %v, want a pass", tc.err, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("classifyNetAdmin(%v) reported a pass", tc.err)
			}
			if got.Cause != tc.want {
				t.Errorf("Cause = %q, want %q", got.Cause, tc.want)
			}
			if got.Capability != CapabilityNetAdmin {
				t.Errorf("Capability = %q, want %q", got.Capability, CapabilityNetAdmin)
			}
		})
	}
}

// TestNetAdminRemedyMatchesTheWitness is the point of the witness: an operator
// must be told to fix the mechanism that is actually broken.
func TestNetAdminRemedyMatchesTheWitness(t *testing.T) {
	missing := classifyNetAdmin(unix.EPERM, func() error { return unix.EOPNOTSUPP })
	if !strings.Contains(missing.Remedy(), "--cap-add NET_ADMIN") {
		t.Errorf("a missing capability was not answered with the capability grant:\n%s", missing.Remedy())
	}
	if !strings.Contains(missing.Remedy(), "CAP_SYS_ADMIN does NOT confer it") {
		t.Errorf("the remedy does not say the two capabilities are independent:\n%s", missing.Remedy())
	}

	filtered := classifyNetAdmin(unix.EPERM, func() error { return unix.EPERM })
	if strings.Contains(filtered.Remedy(), "--cap-add NET_ADMIN;") {
		t.Errorf("a filtered syscall was answered with a capability grant:\n%s", filtered.Remedy())
	}
	if !strings.Contains(filtered.Remedy(), "seccomp") {
		t.Errorf("a filtered syscall was not answered with a profile change:\n%s", filtered.Remedy())
	}
}

// TestIsEthtoolReachable pins what counts as the witness having got through.
func TestIsEthtoolReachable(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"loopback implements no driver info, which means the driver was reached": {unix.EOPNOTSUPP, true},
		"an outright success":            {nil, true},
		"refused by a filter":            {unix.EPERM, false},
		"the socket could not be made":   {errors.New("socket: refused"), false},
		"any other errno is unreachable": {unix.EIO, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isEthtoolReachable(tc.err); got != tc.want {
				t.Errorf("isEthtoolReachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestNetAdminProbeWithInjectedSteps drives the probe end to end, including the
// canceled context.
func TestNetAdminProbeWithInjectedSteps(t *testing.T) {
	t.Run("the capability is held", func(t *testing.T) {
		probe := netAdminProbe(netAdminSteps{
			privileged: func(string) error { return unix.EOPNOTSUPP },
			witness:    func(string) error { return unix.EOPNOTSUPP },
		})
		if err := probe(context.Background()); err != nil {
			t.Fatalf("probe: %v", err)
		}
	})

	t.Run("the probe addresses loopback, which always exists", func(t *testing.T) {
		var seen string
		probe := netAdminProbe(netAdminSteps{
			privileged: func(ifname string) error { seen = ifname; return unix.EOPNOTSUPP },
			witness:    func(string) error { return unix.EOPNOTSUPP },
		})
		_ = probe(context.Background())
		if seen != "lo" {
			t.Errorf("the probe addressed %q; anything but lo can answer ENODEV and teach the guard nothing", seen)
		}
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := netAdminProbe(netAdminSteps{
			privileged: func(string) error { t.Fatal("the probe ran with a canceled context"); return nil },
		})
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestClassifyDRBDControl keeps a missing kernel module from being reported as
// anything a container flag could fix.
func TestClassifyDRBDControl(t *testing.T) {
	cases := map[string]struct {
		err      error
		wantPass bool
		want     Cause
	}{
		"the family resolves":               {nil, true, ""},
		"the module is not loaded":          {unix.ENOENT, false, CauseKernelUnsupported},
		"netlink itself is filtered":        {unix.EPERM, false, CauseSyscallBlocked},
		"netlink is denied":                 {unix.EACCES, false, CauseSyscallBlocked},
		"the address family is unsupported": {unix.EAFNOSUPPORT, false, CauseKernelUnsupported},
		"the protocol is unsupported":       {unix.EPROTONOSUPPORT, false, CauseKernelUnsupported},
		"an errno with no row":              {unix.EIO, false, CauseIndeterminate},
		"a reply too short to interpret":    {errShortNetlinkReply, false, CauseIndeterminate},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyDRBDControl(tc.err)
			if tc.wantPass {
				if got != nil {
					t.Fatalf("classifyDRBDControl(nil) = %v, want a pass", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("classifyDRBDControl(%v) reported a pass", tc.err)
			}
			if got.Cause != tc.want {
				t.Errorf("Cause = %q, want %q", got.Cause, tc.want)
			}
		})
	}
}

// TestDRBDControlRemedyDoesNotSendAnOperatorAfterPrivileges: a missing module's remedy names modprobe, not privileges.
func TestDRBDControlRemedyDoesNotSendAnOperatorAfterPrivileges(t *testing.T) {
	remedy := classifyDRBDControl(unix.ENOENT).Remedy()

	if !strings.Contains(remedy, "modprobe drbd") {
		t.Errorf("the remedy does not name the fix:\n%s", remedy)
	}
	if !strings.Contains(remedy, "CANNOT load a module") {
		t.Errorf("the remedy does not say a container cannot fix this itself:\n%s", remedy)
	}
	if strings.Contains(remedy, "--cap-add NET_ADMIN") {
		t.Errorf("an unloaded module was answered with a capability grant:\n%s", remedy)
	}
}

// TestDRBDControlProbeWithInjectedSteps drives the probe and its cancellation.
func TestDRBDControlProbeWithInjectedSteps(t *testing.T) {
	t.Run("the family resolves", func(t *testing.T) {
		var asked string
		probe := drbdControlProbe(drbdControlSteps{family: func(n string) error { asked = n; return nil }})
		if err := probe(context.Background()); err != nil {
			t.Fatalf("probe: %v", err)
		}
		if asked != "drbd" {
			t.Errorf("the probe resolved %q, want the drbd family", asked)
		}
	})

	t.Run("the module is absent", func(t *testing.T) {
		probe := drbdControlProbe(drbdControlSteps{family: func(string) error { return unix.ENOENT }})
		if err := probe(context.Background()); !errors.Is(err, ErrKernelUnsupported) {
			t.Fatalf("probe = %v, want ErrKernelUnsupported", err)
		}
	})

	t.Run("the context is already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe := drbdControlProbe(drbdControlSteps{
			family: func(string) error { t.Fatal("the probe ran with a canceled context"); return nil },
		})
		if err := probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("probe = %v, want it to carry context.Canceled", err)
		}
	})
}

// TestLiveGenlFamilyResolutionCanSayYes: the resolver must find nlctrl, registered on every generic-netlink kernel.
func TestLiveGenlFamilyResolutionCanSayYes(t *testing.T) {
	// Short enough to be a legal family name: the kernel's GENL_NAMSIZ is 16,
	// and an over-long name answers EINVAL, which would prove nothing about
	// whether the family exists. Measured while writing this.
	const absent = "nosuchfam"

	control := resolveGenlFamily("nlctrl")

	// Where netlink is refused, assert it is reported as a blocked syscall, not an absent module.
	if errors.Is(control, unix.EPERM) || errors.Is(control, unix.EACCES) {
		got := resolveGenlFamily(absent)
		if errors.Is(got, unix.ENOENT) {
			t.Fatalf("netlink is blocked (%v) and an absent family still reported ENOENT; a blocked path must never look like an unloaded module", control)
		}
		if cause := classifyDRBDControl(got).Cause; cause != CauseSyscallBlocked {
			t.Errorf("netlink is blocked and the cause is %q, want %q — an operator must not be sent to modprobe a module that is already there",
				cause, CauseSyscallBlocked)
		}
		return
	}

	// Netlink is reachable, so the resolver must find nlctrl.
	if control != nil {
		t.Fatalf("resolving nlctrl, which every kernel registers: %v — the resolver cannot say yes, so its noes mean nothing", control)
	}

	if err := resolveGenlFamily(absent); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("resolving a family that cannot exist = %v, want ENOENT", err)
	}
}

// TestLiveNetAdminProbeAgreesWithTheEnvironment is the two-sided check on a real
// kernel, against an independent reading of the capability bit.
func TestLiveNetAdminProbeAgreesWithTheEnvironment(t *testing.T) {
	err := netAdminProbe(liveNetAdminSteps())(context.Background())

	if hasCapability(t, capNetAdmin) {
		if err != nil {
			t.Fatalf("CAP_NET_ADMIN is held and the probe refused: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("CAP_NET_ADMIN is absent and the probe passed")
	}
	requireClassified(t, err)
	if !errors.Is(err, ErrPrivilegeMissing) && !errors.Is(err, ErrSyscallBlocked) && !errors.Is(err, ErrPrivilegeOrPolicy) {
		t.Errorf("the probe said %v; with the capability absent the refusal must name the capability or the filter", err)
	}
}

// capNetAdmin is bit 12 of the capability bitmask.
const capNetAdmin = 12

// hasCapability reads CapEff as an independent oracle for tests; the guard itself never does.
func hasCapability(t *testing.T, bit uint) bool {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("reading /proc/self/status, which this test needs as its oracle: %v", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		effective, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			t.Fatalf("parsing CapEff: %v", err)
		}
		return effective&(1<<bit) != 0
	}
	t.Fatal("/proc/self/status carried no CapEff line")
	return false
}
