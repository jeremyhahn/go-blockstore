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

package mountinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The frozen tables in visibility_test.go were copied from a kernel, but they
// were copied ONCE. This file makes the mounts again, here, now, and checks the
// answer against the kernel this test is running on — so a table that a future
// kernel writes differently is caught rather than passing against a snapshot of
// an older one.
//
// It needs a mount namespace, which needs privilege. Rather than requiring
// root, the test re-executes itself inside a user namespace where it is root:
// tmpfs is one of the filesystems a user namespace may mount, which is why the
// mounts below are tmpfs and not something block-backed. Where that is not
// permitted — /proc/sys/kernel/unprivileged_userns_clone off, a seccomp filter,
// a hardened container — the test SKIPS and says which step failed and why.
//
// It never touches the caller's mounts. The child makes / recursively private
// before mounting anything, so nothing it does propagates out, and every mount
// it makes disappears with the namespace when it exits.

// inNamespaceEnv marks the re-executed child. Its presence is the only
// difference between the two halves of this test.
const inNamespaceEnv = "GO_BLOCKSTORE_MOUNTINFO_KERNEL_CHILD"

// baseDirEnv carries the scratch directory from parent to child, because the
// child cannot use t.TempDir — it is a fresh process with its own T.
const baseDirEnv = "GO_BLOCKSTORE_MOUNTINFO_KERNEL_BASE"

// TestAgainstARunningKernelAnAncestorOvermountHidesTheVolume builds the case on
// the live kernel: a volume mounted at base/vol, and then a filesystem mounted
// over base. Nothing names base/vol a second time, and the volume must stop
// being reported as visible there.
func TestAgainstARunningKernelAnAncestorOvermountHidesTheVolume(t *testing.T) {
	if os.Getenv(inNamespaceEnv) != "" {
		runKernelOvermountChild(t)
		return
	}

	relaunchInMountNamespace(t, "base", "base/vol")
}

// relaunchInMountNamespace runs this same test again, by name, inside a user +
// mount namespace where the child is root — and reports a host that will not
// create one as a SKIP naming the step that was refused, never as a pass.
//
// The directories are made in the PARENT's temp dir, which the child inherits
// through baseDirEnv: the child is a fresh process with its own T and no
// t.TempDir of the parent's.
func relaunchInMountNamespace(t *testing.T, dirs ...string) {
	t.Helper()

	base := t.TempDir()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatalf("preparing %s: %v", dir, err)
		}
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), inNamespaceEnv+"=1", baseDirEnv+"="+base)
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
	if err == nil {
		t.Logf("child ran in a user + mount namespace on this kernel:\n%s", indent(string(output)))
		return
	}

	// A namespace this host will not create is a skip, and it says so out loud
	// with the child's own reason attached — a skip nobody can see reads as
	// coverage, which is what this test exists to avoid being.
	if reason := unsupportedReason(string(output)); reason != "" {
		t.Skipf("this host will not run the kernel check: %s\nchild output:\n%s", reason, indent(string(output)))
	}
	t.Fatalf("the kernel check failed: %v\n%s", err, indent(string(output)))
}

// childBase returns the scratch directory the parent prepared.
func childBase(t *testing.T) string {
	t.Helper()
	base := os.Getenv(baseDirEnv)
	if base == "" {
		t.Fatalf("%s is unset, so the child has no directory to mount in", baseDirEnv)
	}
	// Nothing a child mounts may reach the caller's namespace. unshare(1) does
	// exactly this before it runs anything.
	if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatalf("UNSUPPORTED: making / private: %v", err)
	}
	return base
}

// mountTmpfs mounts a tmpfs, marking a refusal as UNSUPPORTED so the parent
// reports it as a skip rather than as a wrong answer.
func mountTmpfs(t *testing.T, source, target string) {
	t.Helper()
	if err := unix.Mount(source, target, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatalf("UNSUPPORTED: mounting tmpfs %s at %s: %v", source, target, err)
	}
}

// recordsAt returns the indices of every record naming a path, in table order.
func recordsAt(entries []Entry, mountPoint string) []int {
	var at []int
	for i, e := range entries {
		if e.MountPoint == mountPoint {
			at = append(at, i)
		}
	}
	return at
}

// runKernelOvermountChild is the half that runs as root inside the namespace.
func runKernelOvermountChild(t *testing.T) {
	base := childBase(t)

	basePath := filepath.Join(base, "base")
	volPath := filepath.Join(basePath, "vol")

	mountTmpfs(t, "tmpBASE", basePath)
	if err := os.MkdirAll(volPath, 0o755); err != nil {
		t.Fatalf("creating %s inside the new tmpfs: %v", volPath, err)
	}
	mountTmpfs(t, "tmpVOL", volPath)

	volMajor, volMinor := deviceOfMount(t, volPath)

	// Before the overmount the volume is reachable at its own path.
	entries, err := Load()
	if err != nil {
		t.Fatalf("reading the mount table: %v", err)
	}
	if got := VisibleMountPointsFor(entries, volMajor, volMinor); len(got) != 1 || got[0] != volPath {
		t.Fatalf("before the overmount, VisibleMountPointsFor(%d:%d) = %v, want %s",
			volMajor, volMinor, got, volPath)
	}

	// Cover the ANCESTOR. Note the path being mounted over is base, not vol.
	mountTmpfs(t, "tmpOVER", basePath)

	entries, err = Load()
	if err != nil {
		t.Fatalf("re-reading the mount table: %v", err)
	}

	// The kernel wrote no second record for the volume's path. If it ever does,
	// this test is checking something other than what it claims to.
	naming := 0
	for _, e := range entries {
		if e.MountPoint == volPath {
			naming++
		}
	}
	if naming != 1 {
		t.Fatalf("%d records name %s; this case is only interesting while exactly one does", naming, volPath)
	}

	if got := MountPointsFor(entries, volMajor, volMinor); len(got) != 1 || got[0] != volPath {
		t.Errorf("MountPointsFor(%d:%d) = %v, want %s: the volume is still mounted", volMajor, volMinor, got, volPath)
	}
	if got := VisibleMountPointsFor(entries, volMajor, volMinor); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(%d:%d) = %v, want none: %s is covered, so a walk to the volume lands inside it",
			volMajor, volMinor, got, basePath)
	}

	// And the kernel agrees, independently of anything this package computed:
	// the volume's path no longer reaches the volume. tmpOVER is empty, so the
	// path does not resolve at all — which is the ENOENT a caller acting on the
	// old answer would get back from umount(2), instead of an unmounted volume.
	var st unix.Stat_t
	switch err := unix.Stat(volPath, &st); {
	case err == unix.ENOENT:
		// The covering filesystem has no such directory: the walk stops there.
	case err != nil:
		t.Errorf("stat %s after the overmount: %v, want ENOENT or the covering device", volPath, err)
	default:
		overMajor, overMinor := deviceOfMount(t, basePath)
		major, minor := unix.Major(st.Dev), unix.Minor(st.Dev)
		if major != overMajor || minor != overMinor {
			t.Errorf("%s resolves to device %d:%d, want the covering filesystem %d:%d — the premise of this test is that it no longer reaches the volume",
				volPath, major, minor, overMajor, overMinor)
		}
		if major == volMajor && minor == volMinor {
			t.Errorf("%s still resolves to the volume %d:%d, so nothing was covered and this test proved nothing",
				volPath, volMajor, volMinor)
		}
	}
}

// deviceOfMount reports the device a PATH resolves to, which is the kernel's
// own answer to the question this package computes from the table.
func deviceOfMount(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return unix.Major(st.Dev), unix.Minor(st.Dev)
}

// unsupportedReason picks out the child failures that mean "this host does not
// allow it" from the ones that mean "the code is wrong", and returns the
// child's own message so the skip names the step that was refused.
//
// The child marks the first kind itself with an UNSUPPORTED prefix. A child
// that could not start at all produces no output to mark, and clone(2) refusing
// CLONE_NEWUSER is reported by the runtime rather than by the test.
func unsupportedReason(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if i := strings.Index(line, "UNSUPPORTED: "); i >= 0 {
			return strings.TrimSpace(line[i+len("UNSUPPORTED: "):])
		}
	}
	switch {
	case strings.TrimSpace(output) == "":
		return "the child produced no output at all, which is what a kernel refusing CLONE_NEWUSER looks like"
	case strings.Contains(output, "operation not permitted"),
		strings.Contains(output, "permission denied"):
		return "creating a user or mount namespace was not permitted"
	}
	return ""
}

// indent keeps the child's output distinguishable from the parent's in a log
// that already has two tests' worth of lines in it.
func indent(s string) string {
	return "\t" + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n\t")
}

// TestUnsupportedReasonNamesTheRefusedStep checks the skip path, because the
// skip path is the one that never runs on a host where the test works — and a
// skip that fired silently, or a real failure misread as a skip, would both
// read as coverage. The inputs are the child's actual output shapes.
func TestUnsupportedReasonNamesTheRefusedStep(t *testing.T) {
	cases := map[string]struct {
		output string
		want   string
	}{
		"a mount the namespace would not permit": {
			output: "=== RUN   TestX\n    f_test.go:1: UNSUPPORTED: mounting tmpfs at /tmp/x: operation not permitted\n--- FAIL: TestX\n",
			want:   "mounting tmpfs at /tmp/x: operation not permitted",
		},
		"a child that never started": {
			output: "",
			want:   "the child produced no output at all, which is what a kernel refusing CLONE_NEWUSER looks like",
		},
		"a clone refused before any test ran": {
			output: "fork/exec /proc/self/exe: operation not permitted\n",
			want:   "creating a user or mount namespace was not permitted",
		},
		"a genuine wrong answer is NOT a skip": {
			output: "=== RUN   TestX\n    f_test.go:1: VisibleMountPointsFor(0:87) = [/tmp/x], want none\n--- FAIL: TestX\n",
			want:   "",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := unsupportedReason(c.output); got != c.want {
				t.Errorf("unsupportedReason = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAgainstARunningKernelASiblingOnTheCoveredPathIsSeparatedByItsAncestor is
// the composite case on the live kernel: two mounts whose mount points render
// as the SAME string, neither the other's parent, told apart only by which of
// them hangs off a mount that has been covered.
//
// The kernel is the oracle here, not the expected values: the marker file read
// back through the path is the filesystem a process actually reaches, and the
// device stat reports is the one umount(2) would detach.
func TestAgainstARunningKernelASiblingOnTheCoveredPathIsSeparatedByItsAncestor(t *testing.T) {
	if os.Getenv(inNamespaceEnv) != "" {
		runKernelCompositeChild(t)
		return
	}
	relaunchInMountNamespace(t, "base", "base/vol")
}

func runKernelCompositeChild(t *testing.T) {
	base := childBase(t)

	basePath := filepath.Join(base, "base")
	volPath := filepath.Join(basePath, "vol")

	mountTmpfs(t, "tmpBASE", basePath)
	if err := os.MkdirAll(volPath, 0o755); err != nil {
		t.Fatalf("creating %s: %v", volPath, err)
	}
	mountTmpfs(t, "tmpVOL", volPath)
	writeMarker(t, volPath, "in-tmpVOL")
	volMajor, volMinor := deviceOfMount(t, volPath)

	// Cover the ancestor, then mount a SECOND filesystem at the very same path
	// string — this one inside the covering filesystem, so its parent is the
	// covering mount and not the covered one.
	mountTmpfs(t, "tmpOVER", basePath)
	if err := os.MkdirAll(volPath, 0o755); err != nil {
		t.Fatalf("creating %s inside the covering tmpfs: %v", volPath, err)
	}
	mountTmpfs(t, "tmpVOL2", volPath)
	writeMarker(t, volPath, "in-tmpVOL2")
	vol2Major, vol2Minor := deviceOfMount(t, volPath)

	if volMajor == vol2Major && volMinor == vol2Minor {
		t.Fatalf("both mounts report device %d:%d, so there is nothing to tell apart and this test proves nothing", volMajor, volMinor)
	}

	// The kernel's own verdict, taken before anything in this package is asked.
	if got := readMarker(t, volPath); got != "in-tmpVOL2" {
		t.Fatalf("%s reads %q, want in-tmpVOL2: the premise is that the path reaches the mount made inside the covering filesystem", volPath, got)
	}

	entries, err := Load()
	if err != nil {
		t.Fatalf("reading the mount table: %v", err)
	}

	at := recordsAt(entries, volPath)
	if len(at) != 2 {
		t.Fatalf("%d records name %s, want exactly 2 — one under the covered ancestor and one under the cover", len(at), volPath)
	}
	lower, upper := entries[at[0]], entries[at[1]]
	if lower.ParentID == upper.ID || upper.ParentID == lower.ID {
		t.Fatalf("records %d and %d are parent and child, so the tree separates them directly and this is the equal-path case, not the composite one", lower.ID, upper.ID)
	}

	if got := VisibleMountPointsFor(entries, volMajor, volMinor); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(%d:%d tmpVOL) = %v, want none: its ancestor %s was mounted over, and the kernel agrees — the path reads %q",
			volMajor, volMinor, got, basePath, "in-tmpVOL2")
	}
	if got := VisibleMountPointsFor(entries, vol2Major, vol2Minor); len(got) != 1 || got[0] != volPath {
		t.Errorf("VisibleMountPointsFor(%d:%d tmpVOL2) = %v, want %s", vol2Major, vol2Minor, got, volPath)
	}
	// The mount is still mounted; only its reachability changed.
	if got := MountPointsFor(entries, volMajor, volMinor); len(got) != 1 || got[0] != volPath {
		t.Errorf("MountPointsFor(%d:%d tmpVOL) = %v, want %s: hidden is not unmounted", volMajor, volMinor, got, volPath)
	}

	entry, ok := EntryAt(entries, volPath)
	if !ok {
		t.Fatalf("EntryAt(%s) found nothing, but the path resolves to a mount", volPath)
	}
	if entry.Major != vol2Major || entry.Minor != vol2Minor {
		t.Errorf("EntryAt(%s) = device %d:%d, want the device the kernel resolves that path to, %d:%d",
			volPath, entry.Major, entry.Minor, vol2Major, vol2Minor)
	}
}

// TestAgainstARunningKernelAMovedMountIsOnTopOfTheRecordAfterIt pins the
// ordering fact the frozen movedOnTopTable rests on, against the kernel running
// now: MS_MOVE re-parents a mount and leaves its record where it already was,
// so the mount ON TOP can be the record listed FIRST.
//
// The assertion that must hold whatever the kernel does with record order is
// the last one: this package's answer equals the device the kernel resolves the
// path to. The inversion itself is reported rather than required, so a kernel
// that stopped inverting would relax this test instead of breaking it.
func TestAgainstARunningKernelAMovedMountIsOnTopOfTheRecordAfterIt(t *testing.T) {
	if os.Getenv(inNamespaceEnv) != "" {
		runKernelMovedChild(t)
		return
	}
	relaunchInMountNamespace(t, "x", "y")
}

func runKernelMovedChild(t *testing.T) {
	base := childBase(t)

	from := filepath.Join(base, "x")
	to := filepath.Join(base, "y")

	mountTmpfs(t, "tmpEARLY", from)
	writeMarker(t, from, "in-tmpEARLY")
	earlyMajor, earlyMinor := deviceOfMount(t, from)

	mountTmpfs(t, "tmpLATE", to)
	writeMarker(t, to, "in-tmpLATE")
	lateMajor, lateMinor := deviceOfMount(t, to)

	// Move the FIRST-created mount on top of the second.
	if err := unix.Mount(from, to, "", unix.MS_MOVE, ""); err != nil {
		t.Fatalf("UNSUPPORTED: moving %s onto %s: %v", from, to, err)
	}

	if got := readMarker(t, to); got != "in-tmpEARLY" {
		t.Fatalf("%s reads %q, want in-tmpEARLY: the moved mount is supposed to be the one on top", to, got)
	}
	visibleMajor, visibleMinor := deviceOfMount(t, to)
	if visibleMajor != earlyMajor || visibleMinor != earlyMinor {
		t.Fatalf("%s resolves to %d:%d, want the moved mount %d:%d", to, visibleMajor, visibleMinor, earlyMajor, earlyMinor)
	}

	entries, err := Load()
	if err != nil {
		t.Fatalf("reading the mount table: %v", err)
	}

	at := recordsAt(entries, to)
	if len(at) != 2 {
		t.Fatalf("%d records name %s, want exactly 2 after the move", len(at), to)
	}
	last := entries[at[len(at)-1]]
	if last.Major == visibleMajor && last.Minor == visibleMinor {
		t.Logf("this kernel lists the mount on top LAST, so the record order agrees with visibility here; the frozen movedOnTopTable is the inverted case")
	} else {
		t.Logf("this kernel lists the mount on top FIRST: the last record naming %s is %d:%d, which is NOT what the path resolves to",
			to, last.Major, last.Minor)
	}

	if got := VisibleMountPointsFor(entries, earlyMajor, earlyMinor); len(got) != 1 || got[0] != to {
		t.Errorf("VisibleMountPointsFor(%d:%d tmpEARLY, the moved mount) = %v, want %s — the kernel resolves that path to it", earlyMajor, earlyMinor, got, to)
	}
	if got := VisibleMountPointsFor(entries, lateMajor, lateMinor); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(%d:%d tmpLATE) = %v, want none: the moved mount landed on it", lateMajor, lateMinor, got)
	}

	entry, ok := EntryAt(entries, to)
	if !ok {
		t.Fatalf("EntryAt(%s) found nothing", to)
	}
	if entry.Major != visibleMajor || entry.Minor != visibleMinor {
		t.Errorf("EntryAt(%s) = device %d:%d, want the device the kernel resolves that path to, %d:%d",
			to, entry.Major, entry.Minor, visibleMajor, visibleMinor)
	}
}

// writeMarker and readMarker are how these tests ask the KERNEL which
// filesystem a path reaches, rather than believing the answer under test. Each
// tmpfs gets a file naming itself, and the name read back through the path is
// the filesystem actually there.
func writeMarker(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte(name), 0o644); err != nil {
		t.Fatalf("writing the marker in %s: %v", dir, err)
	}
}

func readMarker(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "marker"))
	if err != nil {
		t.Fatalf("reading the marker at %s: %v", dir, err)
	}
	return string(b)
}
