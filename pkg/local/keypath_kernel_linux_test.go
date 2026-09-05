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

//go:build kernel_keypath

package local

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The whole key-path guard rests on one claim about the kernel: A MOUNT
// SUBSTITUTES, so a path's meaning before mount(2) is not evidence about its
// meaning after. Everywhere else in this package that claim is asserted against
// a fake whose Mount is a recording — which is exactly the instrument that
// cannot tell a check running before the mount apart from one running after it.
//
// This file makes the mount, here, now, on the kernel the test is running on,
// and asks the SHIPPED containment check the same question on either side of
// it. If a future kernel resolves these paths differently, this goes red rather
// than the design quietly resting on a snapshot of an older one.
//
// It needs a mount namespace, which needs privilege. Rather than requiring
// root, the test re-executes itself inside a user namespace where it is root;
// tmpfs is one of the filesystems a user namespace may mount, which is why the
// volume below is a tmpfs and not something block-backed.
//
// IT IS BEHIND THE kernel_keypath BUILD TAG, AND IT DOES NOT SKIP. Selecting
// the tag is a statement that this host provides unprivileged user + mount
// namespaces, so a host that refuses is a FAILURE — a broken claim, not an
// excuse (conventions/testing-guidelines.md §No Skip Guards; internal/guards
// refuses a runtime skip anywhere in the tree).
//
// A runtime skip was the first answer here and it was the wrong one, for a
// reason worth keeping: measured 2026-09-04, `go test` WITHOUT -v prints
// nothing at all for a passing package — not Skipf, not stderr, not stdout —
// and the CI Test job runs without -v. So a skip in that job is not quiet, it
// is INVISIBLE, and the measurement would have gone missing in exactly the
// environment that gates merges. main reached the same conclusion for
// internal/mountinfo's kernel checks, from the same measurement, in #56.
//
// The verdict logic lives in keypath_kernel_verdict_linux_test.go, UNTAGGED,
// so the decision this file depends on is exercised on every ordinary run.
//
// It never touches the caller's mounts: the child makes / recursively private
// before mounting anything, and every mount it makes dies with the namespace.

// keypathNamespaceEnv marks the re-executed child. Its presence is the only
// difference between the two halves of this test.
const keypathNamespaceEnv = "GO_BLOCKSTORE_KEYPATH_KERNEL_CHILD"

// keypathBaseEnv carries the scratch directory from parent to child, because
// the child cannot use the parent's t.TempDir — it is a fresh process with its
// own T.
const keypathBaseEnv = "GO_BLOCKSTORE_KEYPATH_KERNEL_BASE"

// TestAgainstARunningKernelAMountSubstitutesWhatTheKeyPathResolvesTo is the
// measurement the design rests on, taken rather than assumed.
//
// The fixture is the case no correction to a pre-mount predicate reaches:
// /etc/keys is a symlink to <target>/keys, and <target> is an empty mount
// point, so the link's destination does not exist and the key path cannot be
// resolved through it. The check therefore reports the key OUTSIDE the volume,
// and at that instant it is right.
//
// Then a filesystem carrying keys/vol.key is mounted at the target, by mount(2),
// and the same configured path is asked again.
func TestAgainstARunningKernelAMountSubstitutesWhatTheKeyPathResolvesTo(t *testing.T) {
	if os.Getenv(keypathNamespaceEnv) != "" {
		runKeyPathSubstitutionChild(t)
		return
	}
	relaunchKeyPathTestInMountNamespace(t, "mnt", "etc")
}

// relaunchKeyPathTestInMountNamespace runs this same test again, by name,
// inside a user + mount namespace where the child is root — and reports a host
// that will not create one as a SKIP naming the refused step, never as a pass.
func relaunchKeyPathTestInMountNamespace(t *testing.T, dirs ...string) {
	t.Helper()

	base := t.TempDir()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatalf("preparing %s: %v", dir, err)
		}
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), keypathNamespaceEnv+"=1", keypathBaseEnv+"="+base)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		// Mapping this user to uid 0 inside the namespace is what makes the
		// mounts permitted there. It confers nothing outside it.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	output, err := cmd.CombinedOutput()
	reportKernelChildResult(t, string(output), err)
}

// runKeyPathSubstitutionChild is the half that runs as root inside the
// namespace.
func runKeyPathSubstitutionChild(t *testing.T) {
	base := os.Getenv(keypathBaseEnv)
	if base == "" {
		t.Fatalf("%s is unset, so the child has no directory to mount in", keypathBaseEnv)
	}
	// Nothing this child mounts may reach the caller's namespace.
	if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatalf("UNSUPPORTED: making / private: %v", err)
	}

	target := filepath.Join(base, "mnt")
	link := filepath.Join(base, "etc", "keys")
	if linkErr := os.Symlink(filepath.Join(target, "keys"), link); linkErr != nil {
		t.Fatalf("Symlink: %v", linkErr)
	}
	keyFile := filepath.Join(link, "vol.key")

	// The provider is given the key PATH but a static key provider, not
	// FileKeyProvider: this test measures the containment check, which reads
	// p.keyFile, and never reads the key. Handing a path derived from the
	// environment to a file reader would also be a taint gosec is right to
	// object to in a package whose whole subject is untrusted paths.
	p := newTestProvider(t, newFakeRunner(), withKey, func(o *Options) { o.luksKeyFile = keyFile })
	const why = "the path this volume is being mounted on"

	// ---- before the mount ----
	resolvedBefore, resolveErr := resolveKeyFile(keyFile)
	if resolveErr != nil {
		t.Fatalf("resolveKeyFile before the mount: %v", resolveErr)
	}
	if resolvedBefore != keyFile {
		t.Fatalf("before the mount resolveKeyFile(%q) = %q, want the literal path: "+
			"the dangling link is what makes this case invisible to prediction", keyFile, resolvedBefore)
	}
	if acceptErr := p.checkKeyFileOutside(target, why); acceptErr != nil {
		t.Fatalf("before the mount the check refused (%v); this fixture must be one "+
			"a pre-mount check ACCEPTS or it does not measure the gap", acceptErr)
	}
	if _, readErr := os.ReadFile(keyFile); !os.IsNotExist(readErr) {
		t.Fatalf("before the mount reading %s = %v, want ENOENT", keyFile, readErr)
	}
	devBefore := deviceOfPath(t, target)
	t.Logf("before mount(2): resolves to %s, check accepts, read is ENOENT, target is on device %d:%d",
		resolvedBefore, unix.Major(devBefore), unix.Minor(devBefore))

	// ---- the substitution, by mount(2) ----
	if mountErr := unix.Mount("tmpVOL", target, "tmpfs", 0, "size=1m"); mountErr != nil {
		t.Fatalf("UNSUPPORTED: mounting tmpfs at %s: %v", target, mountErr)
	}
	if mkErr := os.MkdirAll(filepath.Join(target, "keys"), 0o755); mkErr != nil {
		t.Fatalf("creating keys/ inside the mounted volume: %v", mkErr)
	}
	if writeErr := os.WriteFile(filepath.Join(target, "keys", "vol.key"), []byte("VOLUME-KEY"), 0o600); writeErr != nil {
		t.Fatalf("writing the volume's own key file: %v", writeErr)
	}

	// ---- after the mount ----
	//
	// That a FILESYSTEM was substituted, and not merely some directories
	// created, is asserted from the kernel's own device number for the target.
	// Without this the whole file passes against a fixture that never calls
	// mount(2) — an instrument that cannot tell the thing it is named for from
	// an imitation of it, which is the failure this file exists to not repeat.
	devMounted := deviceOfPath(t, target)
	if devMounted == devBefore {
		t.Fatalf("target is still on device %d:%d after mount(2): nothing was substituted",
			unix.Major(devBefore), unix.Minor(devBefore))
	}
	//
	// The kernel first, independently of anything this package computes: the
	// configured path now reads the VOLUME's bytes. That is the exposure, and
	// it is what the check has to be able to see.
	body, readErr := os.ReadFile(keyFile)
	if readErr != nil {
		t.Fatalf("after the mount reading %s: %v", keyFile, readErr)
	}
	if string(body) != "VOLUME-KEY" {
		t.Fatalf("after the mount %s reads %q, want the volume's own bytes: "+
			"without that this test is not the substitution case", keyFile, string(body))
	}

	inside := filepath.Join(target, "keys", "vol.key")
	resolvedAfter, resolveAfterErr := resolveKeyFile(keyFile)
	if resolveAfterErr != nil {
		t.Fatalf("resolveKeyFile after the mount: %v", resolveAfterErr)
	}
	if resolvedAfter != inside {
		t.Errorf("after the mount resolveKeyFile(%q) = %q, want %q", keyFile, resolvedAfter, inside)
	}
	refusal := p.checkKeyFileOutside(target, why)
	if !errors.Is(refusal, ErrKeyFileInsideVolume) {
		t.Fatalf("after the mount the check = %v, want ErrKeyFileInsideVolume: "+
			"the same configured path, the same code, a different filesystem", refusal)
	}
	t.Logf("after mount(2): resolves to %s, check refuses, read is %q", resolvedAfter, string(body))

	// ---- and back ----
	//
	// The substitution is reversible, which is the property that makes it a
	// substitution rather than a one-way effect — and the reason one
	// observation of it always looks like hiding OR publishing but never both.
	if umountErr := unix.Unmount(target, 0); umountErr != nil {
		t.Fatalf("unmounting %s: %v", target, umountErr)
	}
	if devAfter := deviceOfPath(t, target); devAfter != devBefore {
		t.Errorf("target is on device %d:%d after umount(2), want the original %d:%d",
			unix.Major(devAfter), unix.Minor(devAfter), unix.Major(devBefore), unix.Minor(devBefore))
	}
	if _, readErr := os.ReadFile(inside); !os.IsNotExist(readErr) {
		t.Errorf("reading %s after the unmount = %v, want ENOENT: the volume's file went with the mount", inside, readErr)
	}
	if acceptErr := p.checkKeyFileOutside(target, why); acceptErr != nil {
		t.Errorf("after the unmount the check = %v, want it to accept again", acceptErr)
	}
	t.Logf("after umount(2): target is back on device %d:%d and the check accepts again",
		unix.Major(devBefore), unix.Minor(devBefore))
}

// deviceOfPath reports the device a path resolves to, which is the kernel's own
// answer to "is a different filesystem here now".
func deviceOfPath(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Dev
}
