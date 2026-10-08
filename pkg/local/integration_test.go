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

//go:build local_integration

// These tests drive the provider against real LVM, LUKS and filesystems. They
// need root, a loop device, and the lvm2, e2fsprogs and util-linux tooling, so
// they are selected by a build tag rather than skipped at run time,
// and they additionally require GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 to
// acknowledge that they create and destroy storage on the host:
//
//	sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 go test -tags local_integration -race ./pkg/local/
//
// or, equivalently:
//
//	sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 make integration-test-local
//
// Selecting them with a tag and failing when the environment is not there is
// deliberate. A testing.Short guard, or a skip on "not root", turns a suite
// that never runs into a suite that always passes, and the whole reason these
// exist is to catch the things a fake CommandRunner cannot: an lvs column that
// changed name, a device-mapper ioctl the kernel refuses, an option mount(8)
// rejects.
//
// cryptsetup is NOT among the tooling. Nothing here shells out to it — the
// containers are formatted, unlocked and inspected in-process by go-luks2, the
// same way the provider does it — so this suite runs on a host that does not
// have it installed.

package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-blockstore/internal/blkdev"
	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/internal/luks/luktest"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// backingSizeMB is the loopback file every test's volume group is carved from.
// It has to hold a volume, a grown volume and a snapshot's copy-on-write area.
const backingSizeMB = 512

// envDestructive is the explicit acknowledgement this suite requires before it
// touches the host, mirroring GO_BLOCKSTORE_DRBD_ALLOW_DESTRUCTIVE in pkg/drbd.
// The build tag already keeps this file out of an ordinary `go test`, but the
// tag alone does not stop `sudo -E go test -tags local_integration ./...` run
// by reflex on a box whose loop devices and volume groups are not disposable —
// this suite creates and destroys both. Requiring the variable makes the intent
// deliberate; the operator supplies it (the Makefile target does not, matching
// pkg/drbd), e.g. `sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 make integration-test-local`.
const envDestructive = "GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE"

// vgSeq numbers the volume groups within one run so each test gets its own.
var vgSeq atomic.Uint64

// testVG builds a throwaway volume group on a loopback file and returns its
// name, tearing the whole thing down when the test ends.
//
// THE NAME IS UNIQUE PER TEST, and that is load-bearing rather than tidy. Every
// test in this file calls this, and the name used to be derived from the pid
// alone — so all 28 of them shared one volume group name. One test whose
// teardown could not remove its volume group (a LUKS mapping still holding a
// logical volume open, which is a standing flake in the close path) left that
// name in place, and every later test in the same run died in vgcreate with
// "already exists in filesystem". A run with one real failure reported
// seventeen, and the first one was the only one worth reading.
//
// The pid still leads the name so that debris is attributable to a run, and the
// sequence number makes one test's wreckage that test's own problem.
func testVG(t *testing.T) string {
	t.Helper()
	requireDestructiveEnv(t)

	vg := fmt.Sprintf("bsit%dx%d", os.Getpid(), vgSeq.Add(1))
	backing := filepath.Join(t.TempDir(), "backing.img")

	run(t, "truncate", "-s", fmt.Sprintf("%dM", backingSizeMB), backing)

	// The loop device is attached with the LOOP_CTL_GET_FREE / LOOP_SET_FD
	// ioctls rather than by forking losetup(8), which is the same rule the
	// provider itself now follows for LUKS: pure Go unless there is no other
	// way. go-luks2's pkg/loop owns that code.
	loopDev, err := loop.Attach(context.Background(), backing)
	if err != nil {
		t.Fatalf("attaching a loop device to %s: %v", backing, err)
	}
	t.Cleanup(func() { _, _ = loopDev.Detach(context.Background()) })

	run(t, "pvcreate", "--force", "--yes", loopDev.Path())
	run(t, "vgcreate", vg, loopDev.Path())

	// ORDER MATTERS, and t.Cleanup is LIFO: the LAST registered runs FIRST.
	// vgremove cannot remove a volume group whose logical volume a dm-crypt
	// mapping still holds open — which is exactly the state a failed test
	// leaves — so the mapping close is registered second and therefore runs
	// first. Written the other way round it still removes the mapping, just
	// after the vgremove that needed it gone, and the volume group survives the
	// run. Measured: with the registrations swapped, a deliberately abandoned
	// mapping was cleaned up and its volume group still leaked.
	t.Cleanup(func() { _ = exec.Command("vgremove", "--force", vg).Run() })
	t.Cleanup(func() { closeMappingsOf(t, vg) })

	return vg
}

// closeMappingsOf removes the plaintext mappings belonging to one volume group.
//
// Scoped by CONSTRUCTION rather than by pattern-matching something that looks
// like ours: the provider names a mapping "bs-<vg>_<lv>", the volume group name
// is unique to this test, so everything under that prefix was created by this
// test and nothing else can be. go-luks2 #96 refuses cleanup that infers
// ownership from a name; this infers nothing, because the namespace is one this
// test made up moments ago.
//
// It runs BEFORE vgremove and it is best effort. A mapping that will not close
// is reported rather than retried into a hang — the run has already failed by
// the time this matters, and what an operator needs then is to know which
// mapping is stuck.
func closeMappingsOf(t *testing.T, vg string) {
	t.Helper()

	out, err := exec.Command("dmsetup", "ls").Output()
	if err != nil {
		t.Logf("listing device-mapper state to clean up %s: %v", vg, err)
		return
	}

	prefix := mappingPrefix + vg + "_"
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.Fields(line)
		if len(name) == 0 || !strings.HasPrefix(name[0], prefix) {
			continue
		}
		if err := exec.Command("dmsetup", "remove", name[0]).Run(); err != nil {
			t.Logf("LEAKED: mapping %s could not be removed (%v); "+
				"it holds a logical volume open and will block this volume group's removal", name[0], err)
			continue
		}
		t.Logf("cleaned up mapping %s, which the test left behind", name[0])
	}
}

// mustStaticKeyIT builds a passphrase provider for the integration suite. A
// kernel that will not lock memory is a broken host rather than a test failure,
// so it stops the test outright.
func mustStaticKeyIT(t *testing.T, passphrase string) KeyProvider {
	t.Helper()
	stored, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	kp, err := StaticKeyProvider(stored)
	if err != nil {
		t.Fatalf("StaticKeyProvider: %v", err)
	}
	return kp
}

// unlockByHand opens the container on device and activates it under name
// without going through the provider, so a test can plant a mapping the
// provider did not make.
func unlockByHand(ctx context.Context, device, passphrase, name string) error {
	pass, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		return err
	}
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return errors.Join(err, pass.Destroy())
	}
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return errors.Join(err, v.Close(), pass.Destroy())
	}
	_, err = dmcrypt.Activate(ctx, v, key, name)
	key.Destroy()
	return errors.Join(err, v.Close(), pass.Destroy())
}

// luksUUID reads a container's UUID out of its binary header. It is the
// identity that tells a verbatim copy from a reformat, and it is read in
// process rather than by shelling out to `cryptsetup luksUUID`.
func luksUUID(t *testing.T, device string) string {
	t.Helper()
	ctx := context.Background()
	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("opening the LUKS container on %s: %v", device, err)
	}
	defer func() { _ = v.Close() }()

	header, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("reading the LUKS header on %s: %v", device, err)
	}
	return header.UUID()
}

// moveDataOffset rewrites a container's data segment to start at offset,
// producing a container this package did not and could not have formatted.
//
// It exists because go-luks2 offers no offset option: every container it writes
// puts its data at 16 MiB, so a test about a FOREIGN header has no way to ask
// for one. The JSON area is rewritten on disk and both copies' checksums are
// recomputed, so the result is a valid container rather than a corrupted one.
// The keyslot area ends at 290816 bytes, far below any offset a caller of this
// would choose, so nothing is overwritten and the container still opens with
// its original passphrase.
func moveDataOffset(t *testing.T, device string, offset int64) {
	t.Helper()

	luktest.Rewrite(t, device, func(metadata map[string]any) error {
		if err := luktest.SetSegmentOffset(metadata, strconv.FormatInt(offset, 10)); err != nil {
			return err
		}
		// The keyslots area is declared as everything between the two header
		// copies and the data, so it has to move with it or the header
		// contradicts itself and go-luks2 refuses it.
		return luktest.SetKeyslotsSize(metadata, strconv.FormatInt(offset-2*luksHeaderCopyBytes, 10))
	})
}

// The parameters a container this provider formats must carry, spelled out
// here rather than imported: internal/luks does not export its constants, and a
// test that read them from there would pass whatever they said. These are the
// FIPS-deployable choices the header is checked against.
const (
	luksPBKDF       = "pbkdf2"
	luksHash        = "sha512"
	luksCipher      = "aes"
	luksCipherMode  = "xts-plain64"
	luksKeySizeBits = 512
	luksSectorSize  = 4096
)

// luksHeaderCopyBytes is the size of one of the two header copies go-luks2
// writes in front of the keyslots area.
const luksHeaderCopyBytes = 16384

// assertFIPSHeader reads a real LUKS2 header and checks the parameters that
// make the container FIPS-deployable. The library's defaults are not approved —
// an unset KDF is argon2id and an unset hash is SHA-256 — so these are pinned at
// format time and verified here rather than trusted.
//
// The unit suite makes the same assertions against a container formatted onto a
// file (TestNativeFormatPinsFIPSParameters); this one makes them against one
// formatted onto a real logical volume, through the provider, which is the only
// place a parameter can be lost between Options and the disk.
func assertFIPSHeader(t *testing.T, device string) {
	t.Helper()

	metadata := luktest.Read(t, device)

	wantCipher := luksCipher + "-" + luksCipherMode
	for id, keyslot := range metadata.Keyslots {
		if keyslot.KDF.Type != luksPBKDF {
			t.Errorf("keyslot %s KDF = %q, want %q", id, keyslot.KDF.Type, luksPBKDF)
		}
		if keyslot.KDF.Hash != luksHash {
			t.Errorf("keyslot %s KDF hash = %q, want %q", id, keyslot.KDF.Hash, luksHash)
		}
		if keyslot.AF.Hash != luksHash {
			t.Errorf("keyslot %s AF hash = %q, want %q", id, keyslot.AF.Hash, luksHash)
		}
		if want := luksKeySizeBits / 8; keyslot.KeySize != want {
			t.Errorf("keyslot %s key size = %d bytes, want %d", id, keyslot.KeySize, want)
		}
		if keyslot.Area.Encryption != wantCipher {
			t.Errorf("keyslot %s area encryption = %q, want %q", id, keyslot.Area.Encryption, wantCipher)
		}
		if strings.Contains(strings.ToLower(keyslot.KDF.Type), "argon2") {
			t.Errorf("keyslot %s uses %q; argon2 is not FIPS-approved", id, keyslot.KDF.Type)
		}
		// Every iteration count in the header has to clear the SP 800-132 floor.
		if keyslot.KDF.Iterations == nil {
			t.Errorf("keyslot %s records no iteration count", id)
		} else if *keyslot.KDF.Iterations < 1000 {
			t.Errorf("keyslot %s has %d iterations, below the PBKDF2 minimum of 1000",
				id, *keyslot.KDF.Iterations)
		}
	}

	for id, segment := range metadata.Segments {
		if segment.Encryption != wantCipher {
			t.Errorf("segment %s encryption = %q, want %q", id, segment.Encryption, wantCipher)
		}
		if segment.SectorSize != luksSectorSize {
			t.Errorf("segment %s sector size = %d, want %d", id, segment.SectorSize, luksSectorSize)
		}
	}

	for id, digest := range metadata.Digests {
		if strings.Contains(strings.ToLower(digest.Type), "argon2") {
			t.Errorf("digest %s uses %q; argon2 is not FIPS-approved", id, digest.Type)
		}
		if digest.Iterations < 1000 {
			t.Errorf("digest %s has %d iterations, below the PBKDF2 minimum of 1000", id, digest.Iterations)
		}
	}
}

// requireDestructiveEnv gates every test through testVG: it fails unless the
// operator has acknowledged the host cost and is running as root. The
// acknowledgement is checked FIRST, so an invocation that never meant to touch
// this host stops before the root check even reports. A missing environment is
// a hard failure, not a skip — the build tag selected this file, so having been
// compiled in, it was meant to run (same reasoning as pkg/drbd).
func requireDestructiveEnv(t *testing.T) {
	t.Helper()
	if os.Getenv(envDestructive) != "1" {
		t.Fatalf("%s must be set to 1: this suite creates and destroys loop devices, "+
			"volume groups and LUKS volumes on this host. Acknowledge and run it with, e.g.: "+
			"sudo -E %s=1 make integration-test-local", envDestructive, envDestructive)
	}
	if os.Geteuid() != 0 {
		t.Fatal("these tests manage loop devices and LVM and must run as root; re-run with sudo -E")
	}
}

// run executes a setup command, failing the test with its output on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestIntegrationVolumeLifecycle(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 128 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after Provision = %q, want available", status.State)
	}
	if status.SizeBytes < size {
		t.Errorf("SizeBytes = %d, want at least %d", status.SizeBytes, size)
	}

	// Provisioning twice is ErrAlreadyExists, not a second volume.
	_, err = p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Errorf("second Provision = %v, want ErrAlreadyExists", err)
	}

	// Mounting before attaching is a sequencing error the caller can act on.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); !errors.Is(err, common.ErrNotAttached) {
		t.Errorf("Mount before Attach = %v, want ErrNotAttached", err)
	}

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if _, err := os.Stat(info.DevicePath); err != nil {
		t.Fatalf("attached device %s: %v", info.DevicePath, err)
	}

	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{Flags: []string{"noatime"}}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	payload := filepath.Join(target, "payload")
	if err := os.WriteFile(payload, []byte("durable"), 0o600); err != nil {
		t.Fatalf("WriteFile on the mounted volume: %v", err)
	}

	status, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateMounted {
		t.Errorf("State while mounted = %q, want mounted", status.State)
	}

	// Growing a mounted ext4 volume extends the filesystem too.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// Repeating the same request converges instead of looking like a shrink,
	// which is what it would be measured against the extent-rounded size.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("repeated Resize: %v", err)
	}
	// A size LVM rounds up is the same story with a size that is not a whole
	// number of extents.
	if err := p.Resize(ctx, vol.ID, 200000000); err != nil {
		t.Fatalf("Resize to a non-extent-aligned size: %v", err)
	}
	if err := p.Resize(ctx, vol.ID, 200000000); err != nil {
		t.Fatalf("repeated non-extent-aligned Resize: %v", err)
	}
	if err := p.Resize(ctx, vol.ID, 64<<20); !errors.Is(err, common.ErrUnsupported) {
		t.Errorf("shrinking Resize = %v, want ErrUnsupported", err)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	// Unmounting again converges rather than failing.
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("second Unmount: %v", err)
	}

	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	if err := p.Delete(ctx, vol.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Status(ctx, vol.ID); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Status after Delete = %v, want ErrNotFound", err)
	}
}

// TestIntegrationMountTargetWithASpace drives the findmnt path against a real
// mountpoint whose name contains a space — the character whose spelling in
// findmnt's column output depends on the flags and the util-linux version, and
// which therefore decides whether Unmount can match the target it was given.
// Reading the report as JSON takes that dependency away, and this is what says
// so against the findmnt actually installed rather than against a fake.
func TestIntegrationMountTargetWithASpace(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	target := filepath.Join(t.TempDir(), "mount point with spaces")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	// The target has to come back from the kernel's mount table spelled the way
	// it went in — the kernel escapes the spaces, and the parser has to undo
	// that — or none of what follows can match it.
	mounts, err := p.mountpointsFor(ctx, p.lvPath(vol.ID))
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if !contains(mounts, target) {
		t.Fatalf("mountpointsFor = %v, want it to contain %q verbatim", mounts, target)
	}

	// Status sees it as mounted, and Unmount actually unmounts it rather than
	// reporting the convergent "not mounted there".
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateMounted {
		t.Errorf("State = %q, want mounted", status.State)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	after, err := p.mountpointsFor(ctx, p.lvPath(vol.ID))
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if contains(after, target) {
		t.Fatalf("still mounted at %q after Unmount; the target did not round-trip", target)
	}
}

// TestIntegrationMountRefusesASymlinkedTarget drives the real mount path
// against a symlinked target. The mount here is privileged, so following the
// link would attach a filesystem wherever it points.
func TestIntegrationMountRefusesASymlinkedTarget(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// A symlinked final component, and a symlinked parent.
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaParent := filepath.Join(base, "parent")
	if err := os.Symlink(base, viaParent); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	for name, target := range map[string]string{
		"final component":        link,
		"intermediate component": filepath.Join(viaParent, "real"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err == nil {
				_ = p.Unmount(ctx, vol.ID, target)
				t.Fatalf("Mount followed a symlink at %q", target)
			}
		})
	}

	// The real directory still mounts, so the refusal is about symlinks rather
	// than about the mount path being broken.
	if err := p.Mount(ctx, vol.ID, realDir, common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a real directory: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, realDir); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
}

// TestIntegrationMountOptionsReachTheKernel is what the syscall rewrite has to
// earn: the generic options must arrive as kernel flags, not as a filesystem
// data string the kernel never reads. /proc/self/mounts is where that shows.
func TestIntegrationMountOptionsReachTheKernel(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{
		ReadOnly: true,
		Flags:    []string{"nosuid", "nodev", "noexec", "noatime"},
	}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })

	entry := ""
	data := run(t, "cat", "/proc/self/mounts")
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, target) {
			entry = line
		}
	}
	if entry == "" {
		t.Fatalf("no /proc/self/mounts entry for %s", target)
	}
	t.Logf("/proc/self/mounts: %s", entry)

	for _, want := range []string{"ro", "nosuid", "nodev", "noexec", "noatime"} {
		if !strings.Contains(entry, want) {
			t.Errorf("the kernel did not apply %q: %s", want, entry)
		}
	}
}

func TestIntegrationSnapshotAndRestore(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Put known contents on the volume before snapshotting it.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "before"), []byte("snapshotted"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	snaps, err := p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("ListSnapshots on a fresh volume = %v, want empty", snaps)
	}

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Taking a snapshot must not attach anything. Measured on LVM 2.03.16,
	// lvcreate --snapshot over a detached origin whose autoactivation is off
	// leaves BOTH the origin and the new snapshot inactive, with no device
	// nodes — so a caller that had detached the volume still has it detached.
	// Asserted here rather than assumed, because the provider's whole
	// attach/detach model rests on it and a future LVM could change it.
	originStatus, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if originStatus.State != common.VolumeStateAvailable {
		t.Errorf("origin State after Snapshot = %q, want available: snapshotting must not attach it", originStatus.State)
	}
	if _, statErr := os.Stat(p.lvPath(vol.ID)); statErr == nil {
		t.Errorf("origin device node %s exists after Snapshot; the volume was left attached", p.lvPath(vol.ID))
	}

	if _, err := p.Snapshot(ctx, vol.ID, "nightly"); !errors.Is(err, common.ErrAlreadyExists) {
		t.Errorf("duplicate Snapshot = %v, want ErrAlreadyExists", err)
	}

	snaps, err = p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want one snapshot", snaps)
	}
	if snaps[0].ID != snapID || snaps[0].Name != "nightly" || snaps[0].VolumeID != vol.ID {
		t.Errorf("SnapshotInfo = %+v, want it to describe the snapshot just taken", snaps[0])
	}
	if snaps[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; lv_time did not parse against a real lvs")
	}

	// Restoring below the origin's size is refused rather than truncating.
	_, err = p.Provision(ctx, common.VolumeSpec{Name: "toosmall", SizeBytes: 16 << 20, SourceSnapshotID: snapID})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Errorf("undersized restore = %v, want ErrUnsupported", err)
	}

	restored, err := p.Provision(ctx, common.VolumeSpec{Name: "restored", SizeBytes: size, SourceSnapshotID: snapID})
	if err != nil {
		t.Fatalf("Provision from snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	// The origin was detached when the restore ran, and reading the snapshot
	// activates the origin along with it. It has to end up detached again.
	originStatus, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if originStatus.State != common.VolumeStateAvailable {
		t.Errorf("origin State after restore = %q, want available", originStatus.State)
	}

	// The restored volume carries the origin's filesystem and contents.
	restoreTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoreTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	if err := p.Mount(ctx, restored.ID, restoreTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(restoreTarget, "before"))
	if err != nil {
		t.Fatalf("reading the restored file: %v", err)
	}
	if string(got) != "snapshotted" {
		t.Errorf("restored contents = %q, want %q", got, "snapshotted")
	}
	if err := p.Unmount(ctx, restored.ID, restoreTarget); err != nil {
		t.Fatalf("Unmount restored: %v", err)
	}
	if err := p.Detach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Detach restored: %v", err)
	}

	// Deleting the snapshot leaves the restored volume intact, because the
	// restore was a copy rather than a dependent volume.
	if err := p.DeleteSnapshot(ctx, snapID); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := p.DeleteSnapshot(ctx, snapID); !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Errorf("second DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
	}
	if _, err := p.Status(ctx, restored.ID); err != nil {
		t.Errorf("restored volume did not survive its snapshot: %v", err)
	}
}

// TestIntegrationRestoreDoesNotDisturbAnAttachedOrigin is the coupling that
// matters most in practice: LVM activates an origin and its snapshots as one
// unit, so a restore that switched the snapshot off afterwards takes the
// origin's device node with it.
//
// The origin here is attached but deliberately not mounted, which is the state
// that actually breaks. A mounted origin is protected by LVM itself — lvchange
// refuses to deactivate a logical volume with a filesystem open on it — so a
// test that mounted the origin would pass against the bug and prove nothing.
// TestIntegrationRestoreAfterGrowingTheOrigin drives the case where an origin's
// current size and the size its snapshot presents have diverged. LVM permits
// growing an origin that has snapshots while it is INACTIVE, which is the state
// this provider leaves volumes in, so the divergence arises through this API
// alone: Provision, Snapshot, Resize, restore.
func TestIntegrationRestoreAfterGrowingTheOrigin(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const imageSize = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: imageSize, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Known contents, so the restored copy can be checked rather than assumed.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "before"), []byte("point in time"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Grow the origin AFTER snapshotting. From here the two sizes differ.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize the origin: %v", err)
	}

	snaps, err := p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want one", snaps)
	}

	// The restore is sized for the IMAGE, which is now smaller than the origin.
	// Sizing from the origin would reject this outright.
	restored, err := p.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        imageSize,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("restore sized for the snapshot image: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	restoreTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoreTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, restored.ID, "test-node") })
	if err := p.Mount(ctx, restored.ID, restoreTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, restored.ID, restoreTarget) })

	got, err := os.ReadFile(filepath.Join(restoreTarget, "before"))
	if err != nil {
		t.Fatalf("reading the restored file: %v", err)
	}
	if string(got) != "point in time" {
		t.Errorf("restored contents = %q, want the snapshot's", got)
	}
}

func TestIntegrationRestoreDoesNotDisturbAnAttachedOrigin(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	restored, err := p.Provision(ctx, common.VolumeSpec{Name: "restored", SizeBytes: size, SourceSnapshotID: snapID})
	if err != nil {
		t.Fatalf("Provision from snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if status.State != common.VolumeStateAttached {
		t.Errorf("origin State after restore = %q, want it still attached", status.State)
	}
	if _, err := os.Stat(p.lvPath(vol.ID)); err != nil {
		t.Errorf("the origin's device node did not survive the restore: %v", err)
	}

	// And it is still a working block device, not just a listed one: mounting
	// it after the restore has to succeed.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("mounting the origin after the restore: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
}

// TestIntegrationWipeOnDelete drives the wipe against a real logical volume:
// that blkdiscard --zeroout accepts the flag and the device, that it clears the
// volume, and that Delete still removes it afterwards.
//
// It deliberately does not try to demonstrate the exposure the wipe exists to
// close — that a deleted volume's contents survive in the extents LVM hands to
// the next volume. Whether they survive depends on the storage underneath: with
// devices/issue_discards=1 and a backing device that supports discard (a
// loopback file on a modern filesystem, which is what these tests build on),
// lvremove discards the extents and they read back as zeroes regardless of this
// option. The LVM default is issue_discards=0, and rotating disks do not
// discard at all, which is where the option earns its keep. A test asserting
// remanence here would pass for reasons that have nothing to do with the code.
func TestIntegrationWipeOnDelete(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node", WipeOnDelete: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 32 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secrets", SizeBytes: size})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	const marker = "SENSITIVE-TENANT-DATA"
	writeMarker(t, info.DevicePath, marker)
	if !markerPresent(t, info.DevicePath, marker) {
		t.Fatal("the marker did not reach the device; the rest of this test would prove nothing")
	}

	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := p.Delete(ctx, vol.ID); err != nil {
		t.Fatalf("Delete with WipeOnDelete: %v", err)
	}
	if _, err := p.Status(ctx, vol.ID); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Status after a wiping Delete = %v, want ErrNotFound", err)
	}

	// The volume group is usable again: the wipe left nothing that stops the
	// extents being reallocated.
	next, err := p.Provision(ctx, common.VolumeSpec{Name: "next", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision after a wiping Delete: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, next.ID) })
}

// markerOffset is where the wipe test places its marker: past the first few
// kilobytes, which lvcreate zeroes on its own.
const markerOffset = 8 << 20

// writeMarker puts a recognizable string into a block device.
func writeMarker(t *testing.T, device, marker string) {
	t.Helper()
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()

	// Block devices take aligned writes, so the marker goes inside a full
	// sector rather than being written as a short string.
	sector := make([]byte, 4096)
	copy(sector, marker)
	if _, err := f.WriteAt(sector, markerOffset); err != nil {
		t.Fatalf("writing to %s: %v", device, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing %s: %v", device, err)
	}
}

// markerPresent reports whether the marker is readable back from the device.
func markerPresent(t *testing.T, device, marker string) bool {
	t.Helper()
	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("opening %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 4096)
	if _, err := f.ReadAt(buf, markerOffset); err != nil {
		t.Fatalf("reading %s: %v", device, err)
	}
	return bytes.Contains(buf, []byte(marker))
}

func TestIntegrationEncryptedVolume(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// The logical volume itself holds a LUKS container, not a filesystem. This
	// has to be probed while the volume is attached: Provision leaves it
	// deactivated, and a deactivated volume has no device node to probe.
	fsType, err := p.probeFSType(ctx, p.lvPath(vol.ID))
	if err != nil {
		t.Fatalf("probeFSType: %v", err)
	}
	if fsType != fsTypeLUKS {
		t.Fatalf("the provisioned volume is %q, want %q", fsType, fsTypeLUKS)
	}

	// What the header actually says, read off the real container on a real
	// logical volume. The unit suite asserts the same parameters against a
	// container formatted onto a file; this one is the only place that catches
	// a parameter lost between Options and a block device.
	assertFIPSHeader(t, p.lvPath(vol.ID))
	if info.DevicePath != p.cryptPath(vol.ID) {
		t.Errorf("DevicePath = %q, want the plaintext mapping %q", info.DevicePath, p.cryptPath(vol.ID))
	}

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("encrypted at rest"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// An attached encrypted volume is REFUSED rather than resized, and the
	// mapping the mount is sitting on is untouched by the refusal — which is
	// checked below by continuing to use it.
	if err := p.Resize(ctx, vol.ID, 96<<20); !errors.Is(err, ErrResizeWhileAttached) {
		t.Fatalf("Resize while attached = %v, want ErrResizeWhileAttached", err)
	}
	if _, err := os.ReadFile(filepath.Join(target, "payload")); err != nil {
		t.Fatalf("the mount did not survive the refused resize: %v", err)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// Detached, the same resize is served: the provider unlocks the container
	// itself, grows the filesystem inside it and locks it again.
	if err := p.Resize(ctx, vol.ID, 96<<20); err != nil {
		t.Fatalf("Resize while detached: %v", err)
	}

	// Locked again, the volume is not attached and cannot be mounted.
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after Detach = %q, want available", status.State)
	}

	// Re-attaching unlocks it again and the data is still there.
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("re-Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("re-Mount: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(target, "payload"))
	if err != nil {
		t.Fatalf("reading after re-unlock: %v", err)
	}
	if string(got) != "encrypted at rest" {
		t.Errorf("contents = %q, want them preserved across a lock/unlock cycle", got)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
}

// TestIntegrationWrongKeyIsRejected checks that the passphrase is actually
// protecting the container rather than being accepted decoratively.
// TestIntegrationDetachedEncryptedResize proves the filesystem inside a locked
// container really grows. The volume is resized while DETACHED — the state
// where the provider has to unlock it itself, because Attach only opens a
// container and never grows what is inside one — and then attached and mounted
// so the filesystem's own idea of its size can be read back.
func TestIntegrationDetachedEncryptedResize(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "detached-resize-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const initial = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: initial, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	before := mountedFSBytes(t, ctx, p, vol.ID, target)

	// Resize with the volume detached and locked — Provision left it that way.
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Fatalf("State = %q, want available: this test is about the detached path", status.State)
	}
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize while detached: %v", err)
	}

	// It has to come back the way it went in: detached, and still locked.
	status, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status after resize: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after resize = %q, want available: the volume was left unlocked or activated", status.State)
	}

	after := mountedFSBytes(t, ctx, p, vol.ID, target)
	t.Logf("filesystem bytes: before=%d after=%d", before, after)
	if after <= before {
		t.Errorf("filesystem is %d bytes after a resize from %d bytes; it was never grown", after, before)
	}
	if after < 128<<20 {
		t.Errorf("filesystem is %d bytes, want it grown to roughly the new 192 MiB volume", after)
	}
}

// mountedFSBytes attaches and mounts a volume, reads the filesystem's own total
// size, and puts the volume back as it found it.
func mountedFSBytes(t *testing.T, ctx context.Context, p *Provider, volID, target string) int64 {
	t.Helper()
	if _, err := p.Attach(ctx, volID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, volID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	defer func() {
		if err := p.Unmount(ctx, volID, target); err != nil {
			t.Fatalf("Unmount: %v", err)
		}
		if err := p.Detach(ctx, volID, "test-node"); err != nil {
			t.Fatalf("Detach: %v", err)
		}
	}()

	// The filesystem's own total, not the block device's — that is the number a
	// resize is supposed to move.
	out := strings.TrimSpace(run(t, "df", "--block-size=1", "--output=size", target))
	lines := strings.Split(out, "\n")
	size, err := strconv.ParseInt(strings.TrimSpace(lines[len(lines)-1]), 10, 64)
	if err != nil {
		t.Fatalf("reading df output %q: %v", out, err)
	}
	return size
}

// TestIntegrationForeignMappingIsRefused builds the hazard for real: a mapping
// opened by hand under this provider's deterministic name, over a DIFFERENT
// volume. device-mapper reports it active under that name, so a provider
// trusting the name would return somebody else's decrypted device from Attach.
func TestIntegrationForeignMappingIsRefused(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "foreign-mapping-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ours, err := p.Provision(ctx, common.VolumeSpec{Name: "ours", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision ours: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, ours.ID) })

	theirs, err := p.Provision(ctx, common.VolumeSpec{Name: "theirs", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision theirs: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, theirs.ID) })

	// Open "theirs" by hand under the name the provider reserves for "ours".
	run(t, "lvchange", "--activate", "y", "--yes", p.lvRef(theirs.ID))
	stolen := p.mappingName(ours.ID)
	if err := unlockByHand(ctx, p.lvPath(theirs.ID), "foreign-mapping-passphrase", stolen); err != nil {
		t.Fatalf("setting up the foreign mapping: %v", err)
	}
	t.Cleanup(func() {
		_ = dmcrypt.Deactivate(ctx, stolen)
		_ = exec.Command("lvchange", "--activate", "n", "--yes", p.lvRef(theirs.ID)).Run()
	})

	// The mapping really is live under our name — the hazard is present, not
	// hypothetical.
	if _, err := dmcrypt.Lookup(ctx, stolen); err != nil {
		t.Fatalf("the foreign mapping %q is not active; this test proves nothing", stolen)
	}

	// The provider must refuse it rather than hand it back as "ours".
	info, err := p.Attach(ctx, ours.ID, "test-node")
	if err == nil {
		t.Fatalf("Attach adopted the foreign mapping and returned %q", info.DevicePath)
	}
	t.Logf("Attach correctly refused: %v", err)
}

func TestIntegrationWrongKeyIsRejected(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	good, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "the-right-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := good.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = good.Delete(ctx, vol.ID) })

	bad, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		KeyProvider: mustStaticKeyIT(t, "the-wrong-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := bad.Attach(ctx, vol.ID, "test-node"); err == nil {
		t.Fatal("Attach succeeded with the wrong passphrase")
	}
}

// TestIntegrationHostileNamesNeverReachLVM re-checks the validation rule
// against the real tools: a rejected name must produce common.ErrInvalidArgument and leave the
// volume group untouched.
func TestIntegrationHostileNamesNeverReachLVM(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, hostile := range []string{"data; lvremove -f " + vg, "../etc", "-wipesignatures", "$(id)"} {
		_, err := p.Provision(ctx, common.VolumeSpec{Name: hostile, SizeBytes: 32 << 20})
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Provision(%q) = %v, want common.ErrInvalidArgument", hostile, err)
		}
	}

	lvs, err := p.listLVs(ctx)
	if err != nil {
		t.Fatalf("listLVs: %v", err)
	}
	if len(lvs) != 0 {
		t.Errorf("the volume group holds %v after rejected requests, want nothing", lvs)
	}
}

// deviceSizeBytes reads a block device's real size from the kernel, which is
// the only authority on how much of a container a caller can actually write to.
func deviceSizeBytes(t *testing.T, device string) int64 {
	t.Helper()
	out := strings.TrimSpace(run(t, "blockdev", "--getsize64", device))
	size, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		t.Fatalf("blockdev --getsize64 %s returned %q: %v", device, out, err)
	}
	return size
}

// TestIntegrationEncryptedVolumeDeliversTheRequestedCapacity is the assertion
// behind the sizing rule: VolumeSpec.SizeBytes is what the CALLER CAN USE, so
// the plaintext mapping an encrypted volume attaches as must be at least that
// large. Before the rule it was a LUKS header SHORT of it, and nothing said so.
//
// It also pins the constant the sizing arithmetic is built on. luksHeaderBytes
// is a measurement — 16 MiB, taken from cryptsetup 2.7.0 and re-taken from
// go-luks2 with the parameters this provider formats with — and a measurement
// in a comment rots. Here the
// same figure is derived from a real container: the logical volume's size less
// the mapping's, which is by definition what the header cost.
func TestIntegrationEncryptedVolumeDeliversTheRequestedCapacity(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const requested = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "sized", SizeBytes: requested, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	// THE assertion. The device the caller was handed is the plaintext mapping,
	// and it holds at least what was asked for.
	mapping := deviceSizeBytes(t, info.DevicePath)
	if mapping < requested {
		t.Errorf("the plaintext mapping is %d bytes, %d short of the %d that were requested",
			mapping, requested-mapping, requested)
	}

	// And the constant the arithmetic used is the overhead that really applied.
	backing := deviceSizeBytes(t, p.lvPath(vol.ID))
	if overhead := backing - mapping; overhead != luksHeaderBytes {
		t.Errorf("this container's header cost %d bytes; luksHeaderBytes says %d. "+
			"The constant was measured on cryptsetup 2.7.0 and again on go-luks2 with the parameters "+
			"luksFormat pins; if the layout has changed, re-measure it rather than adjusting this test",
			overhead, luksHeaderBytes)
	}

	// Status reports the usable figure, in the units the volume was asked for.
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.SizeBytes < requested {
		t.Errorf("Status.SizeBytes = %d, below the %d requested", status.SizeBytes, requested)
	}
	if status.SizeBytes != mapping {
		t.Errorf("Status.SizeBytes = %d but the mapping is %d; Status is not reporting usable capacity",
			status.SizeBytes, mapping)
	}

	// The rule holds across a resize too, which is the other place the
	// arithmetic lives. It has to be done detached — an attached encrypted
	// volume is refused, see ErrResizeWhileAttached — so the volume goes down
	// and comes back up around it, which is also what a caller has to do.
	const grown = 128 << 20
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach before resize: %v", err)
	}
	if err := p.Resize(ctx, vol.ID, grown); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	regrown, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("re-Attach after resize: %v", err)
	}
	if got := deviceSizeBytes(t, regrown.DevicePath); got < grown {
		t.Errorf("after Resize the mapping is %d bytes, below the %d requested", got, grown)
	}
}

// TestIntegrationReencryptingRestore is ruling #11b end to end: a snapshot of a
// PLAINTEXT volume restored by a provider configured to encrypt produces an
// encrypted volume holding the same data.
//
// The two assertions that matter pull in opposite directions and are both
// required. The data has to survive — attach, mount, and the files read back
// byte-identical — and the plaintext must NOT survive anywhere it could be
// read: the logical volume is scanned for the marker, and finding it would mean
// the copy went onto the extents instead of through the mapping, which is the
// silent downgrade this path exists to avoid.
func TestIntegrationReencryptingRestore(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	// A plain provider makes the source volume and the snapshot.
	plain, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	src, err := plain.Provision(ctx, common.VolumeSpec{Name: "src", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision source: %v", err)
	}
	t.Cleanup(func() { _ = plain.Delete(ctx, src.ID) })

	const marker = "restore-me-through-dm-crypt"
	target := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := plain.Attach(ctx, src.ID, "test-node"); err != nil {
		t.Fatalf("Attach source: %v", err)
	}
	if err := plain.Mount(ctx, src.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount source: %v", err)
	}
	payload := bytes.Repeat([]byte(marker+"\n"), 512)
	if err := os.WriteFile(filepath.Join(target, "payload"), payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := plain.Unmount(ctx, src.ID, target); err != nil {
		t.Fatalf("Unmount source: %v", err)
	}
	if err := plain.Detach(ctx, src.ID, "test-node"); err != nil {
		t.Fatalf("Detach source: %v", err)
	}

	snapID, err := plain.Snapshot(ctx, src.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	t.Cleanup(func() { _ = plain.DeleteSnapshot(ctx, snapID) })

	// An encrypting provider restores it. Before ruling #11b this returned
	// ErrUnsupported.
	enc, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New encrypting: %v", err)
	}

	restored, err := enc.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        64 << 20,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("re-encrypting restore: %v", err)
	}
	t.Cleanup(func() { _ = enc.Delete(ctx, restored.ID) })

	info, err := enc.Attach(ctx, restored.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	t.Cleanup(func() { _ = enc.Detach(ctx, restored.ID, "test-node") })

	// It really is a container, formatted the way this provider formats them,
	// and the caller was handed the mapping rather than the raw volume.
	if fsType, probeErr := enc.probeFSType(ctx, enc.lvPath(restored.ID)); probeErr != nil {
		t.Fatalf("probeFSType: %v", probeErr)
	} else if fsType != fsTypeLUKS {
		t.Fatalf("the restored volume is %q, want a LUKS container", fsType)
	}
	assertFIPSHeader(t, enc.lvPath(restored.ID))
	if info.DevicePath != enc.cryptPath(restored.ID) {
		t.Errorf("DevicePath = %q, want the plaintext mapping %q", info.DevicePath, enc.cryptPath(restored.ID))
	}

	// The sizing rule holds here too: usable capacity is what was asked for.
	if got := deviceSizeBytes(t, info.DevicePath); got < 64<<20 {
		t.Errorf("the restored mapping is %d bytes, below the %d requested", got, 64<<20)
	}

	// The data survived, byte for byte.
	restoredTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoredTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := enc.Mount(ctx, restored.ID, restoredTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	t.Cleanup(func() { _ = enc.Unmount(ctx, restored.ID, restoredTarget) })

	got, err := os.ReadFile(filepath.Join(restoredTarget, "payload"))
	if err != nil {
		t.Fatalf("reading the restored payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("the restored payload differs from the source: %d bytes vs %d", len(got), len(payload))
	}

	// And the plaintext is nowhere on the volume's own extents. This is the
	// assertion that would catch a copy written to the logical volume instead
	// of through the mapping — which would pass every check above.
	if markerPresent(t, enc.lvPath(restored.ID), marker) {
		t.Error("the source's plaintext is readable on the restored volume's extents; " +
			"the copy did not go through the dm-crypt mapping")
	}
}

// TestIntegrationEncryptedSourceRestorePreservesTheHeader is the other half of
// ruling #11b. A snapshot of an ENCRYPTED volume is ciphertext at the logical
// volume level, so it is copied verbatim and the restored volume keeps its
// source's header — which is checked here by UUID, the one field that would
// change if the container had been reformatted.
//
// Reformatting would be destructive rather than merely different: a fresh
// header carries a fresh master key, and ciphertext copied over it decrypts to
// nothing. The mount at the end is what proves that did not happen.
func TestIntegrationEncryptedSourceRestorePreservesTheHeader(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	src, err := p.Provision(ctx, common.VolumeSpec{Name: "src", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, src.ID) })

	target := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, src.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, src.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	payload := []byte("ciphertext lineage")
	if err := os.WriteFile(filepath.Join(target, "payload"), payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The source's header identity, read before the copy.
	srcUUID := luksUUID(t, p.lvPath(src.ID))
	if srcUUID == "" {
		t.Fatal("the source container's header reports no UUID")
	}

	if err := p.Unmount(ctx, src.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, src.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	snapID, err := p.Snapshot(ctx, src.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.DeleteSnapshot(ctx, snapID) })

	// Sized at the source's USABLE capacity, which under the sizing rule is
	// simply the size the source was provisioned at: the header the source
	// carries is subtracted from its image and added back to the restore, and
	// the two cancel. That the same number works on both ends is the point of
	// the rule.
	restored, err := p.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        64 << 20,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("restore from an encrypted snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	info, err := p.Attach(ctx, restored.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, restored.ID, "test-node") })

	// Same header, which is what "copied verbatim" means and what makes the
	// source's passphrase the one that opens it.
	restoredUUID := luksUUID(t, p.lvPath(restored.ID))
	if restoredUUID != srcUUID {
		t.Errorf("the restored volume's LUKS UUID is %q, want the source's %q; the container was reformatted",
			restoredUUID, srcUUID)
	}

	// And it opens and holds the data, which is the check that a reformat would
	// have failed.
	restoredTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoredTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, restored.ID, restoredTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, restored.ID, restoredTarget) })

	got, err := os.ReadFile(filepath.Join(restoredTarget, "payload"))
	if err != nil {
		t.Fatalf("reading the restored payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("restored payload = %q, want %q", got, payload)
	}
	_ = info
}

// TestIntegrationEncryptedRestoreRefusesAKeyThatWouldNotOpenIt drives the
// key check against a real LUKS header rather than a fake error.
//
// The KeyProvider here holds a distinct key per volume, which the interface
// explicitly allows — and which is exactly what makes a verbatim restore
// dangerous, since the restored volume opens only with its SOURCE's passphrase.
// Without the check this restore would succeed and the volume would be
// unreadable forever.
func TestIntegrationEncryptedRestoreRefusesAKeyThatWouldNotOpenIt(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	perVolume := func(_ context.Context, volID string) (*enclave.MemoryEnclave, error) {
		return enclave.NewMemoryEnclave([]byte("passphrase-for-" + volID))
	}

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: perVolume,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	src, err := p.Provision(ctx, common.VolumeSpec{Name: "src", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, src.ID) })

	snapID, err := p.Snapshot(ctx, src.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.DeleteSnapshot(ctx, snapID) })

	// "restored" gets a different passphrase from "src", so the copied header
	// would not open under it.
	_, err = p.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        64 << 20,
		SourceSnapshotID: snapID,
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}

	// Refused before anything was created: no unreadable volume was left
	// behind for an operator to find later.
	if _, statusErr := p.Status(ctx, "restored"); !errors.Is(statusErr, common.ErrNotFound) {
		t.Errorf("Status of the refused volume = %v, want ErrNotFound; a volume was left behind", statusErr)
	}
}

// lvTags reads the LVM tags on a logical volume straight from lvs.
func lvTags(t *testing.T, vg, lv string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "lvs", "--noheadings", "-o", "lv_tags", vg+"/"+lv))
}

// TestIntegrationEncryptionIsRememberedAcrossDetach is the ruling that made the
// tag exist, driven against real LVM.
//
// A detached encrypted volume has no device node — there is nothing to probe,
// and Status holds no lock and will not activate one to look. Before the tag it
// could only report its backing size, a LUKS header more than its usable
// capacity. Here the same volume is asked while attached and while detached and
// has to give the same answer both times.
func TestIntegrationEncryptionIsRememberedAcrossDetach(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const requested = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "remembered", SizeBytes: requested, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Provision leaves the volume DETACHED, so this is the state the tag exists
	// for — and it is the very first thing asked of the volume.
	if tags := lvTags(t, vg, vol.ID); !strings.Contains(tags, encryptedTagPrefix) {
		t.Fatalf("lv_tags = %q, want it to contain %q", tags, encryptedTagPrefix)
	}

	detached, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status while detached: %v", err)
	}
	if detached.State != common.VolumeStateAvailable {
		t.Errorf("State = %q, want available", detached.State)
	}
	if detached.SizeBytes < requested {
		t.Errorf("detached Status.SizeBytes = %d, below the %d requested; "+
			"the tag did not carry the volume's encryption across the detach", detached.SizeBytes, requested)
	}

	// The same question with the volume up, where discovery answers it instead.
	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	attached, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status while attached: %v", err)
	}
	if attached.SizeBytes != detached.SizeBytes {
		t.Errorf("Status reports %d attached and %d detached; the two sources disagree",
			attached.SizeBytes, detached.SizeBytes)
	}
	// And both agree with the device the caller actually got.
	if mapping := deviceSizeBytes(t, info.DevicePath); attached.SizeBytes != mapping {
		t.Errorf("Status.SizeBytes = %d but the mapping is %d", attached.SizeBytes, mapping)
	}
}

// TestIntegrationLegacyVolumeIsRetaggedOnAttach is the migration path. A volume
// provisioned before the tag existed carries none; the fleet heals one attach at
// a time rather than needing a migration pass.
//
// The legacy volume is built by provisioning normally and then stripping the
// tag, which is exactly the on-disk state such a volume is in.
func TestIntegrationLegacyVolumeIsRetaggedOnAttach(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const requested = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "legacy", SizeBytes: requested, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	run(t, "lvchange", "--deltag", encryptedTagFor(luksHeaderBytes), vg+"/"+vol.ID)
	if tags := lvTags(t, vg, vol.ID); strings.Contains(tags, encryptedTagPrefix) {
		t.Fatalf("the tag survived deltag: %q", tags)
	}

	// Untagged and detached: the documented legacy fallback. It reports the
	// BACKING size, which OVER-states usable capacity by exactly one header —
	// pinned here rather than merely described, because this is the deviation
	// the ruling scoped down to legacy volumes and it should not drift.
	legacy, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	backing := deviceSizeBytesOfLV(t, vg, vol.ID)
	if legacy.SizeBytes != backing {
		t.Errorf("untagged legacy volume reports %d, want the backing size %d — "+
			"the documented fallback for a volume provisioned before the tag existed",
			legacy.SizeBytes, backing)
	}

	// One attach repairs it.
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if tags := lvTags(t, vg, vol.ID); !strings.Contains(tags, encryptedTagPrefix) {
		t.Fatalf("after Attach lv_tags = %q, want the repair to have written %q", tags, encryptedTagPrefix)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// And having healed, the detached answer is right.
	healed, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status after the repair: %v", err)
	}
	if healed.SizeBytes < requested {
		t.Errorf("after the repair the detached Status.SizeBytes = %d, below the %d requested",
			healed.SizeBytes, requested)
	}
	// Specifically: it stopped reporting the backing size and started
	// subtracting the header.
	if healed.SizeBytes != backing-luksHeaderBytes {
		t.Errorf("after the repair Status.SizeBytes = %d, want the backing %d less the %d header",
			healed.SizeBytes, backing, luksHeaderBytes)
	}
}

// deviceSizeBytesOfLV reads a logical volume's size from lvs, which works
// whether or not the volume is active — unlike blockdev, which needs a device
// node and so cannot be asked about a detached volume at all.
func deviceSizeBytesOfLV(t *testing.T, vg, lv string) int64 {
	t.Helper()
	out := strings.TrimSpace(run(t, "lvs", "--noheadings", "--units", "b", "--nosuffix", "-o", "lv_size", vg+"/"+lv))
	size, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		t.Fatalf("lvs lv_size for %s/%s returned %q: %v", vg, lv, out, err)
	}
	return size
}

// TestIntegrationDetachedForeignHeaderReportsCorrectly is Codex's finding driven
// against real LVM and a real container: a volume restored VERBATIM from a
// container whose header is not the size this package formats.
//
// The restore measures that header to size the volume, so the tag records the
// measured number. Recording only "encrypted" and assuming 16 MiB would misstate
// the detached capacity by the difference — and in the direction that matters,
// since a header larger than the default makes Status over-state what the volume
// can hold.
//
// The foreign container is made by formatting one with this package's own
// parameters and then MOVING its data segment to a deliberately non-default
// offset, and snapshotting it. Rewriting the header is how a foreign container
// gets built without a foreign tool: go-luks2 has no offset option, and every
// container it formats lands at 16 MiB, so there is no way to ask it for one
// that differs. The rewrite is honest — the header is re-checksummed and the
// container still opens with the same passphrase, since the keyslot area ends
// well before 4 MiB — and it is what a container written by an older release,
// or by an operator's own cryptsetup --offset, looks like to this provider.
func TestIntegrationDetachedForeignHeaderReportsCorrectly(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	const passphrase = "integration-test-passphrase"
	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, passphrase),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A container this package did NOT format: same key, but an explicit
	// 4 MiB payload offset instead of the 16 MiB luksFormat pins.
	const foreignHeader = 4 << 20
	run(t, "lvcreate", "--yes", "--name", "foreign", "--size", "64M", "--setautoactivation", "n", vg)
	t.Cleanup(func() { _ = exec.Command("lvremove", "--force", vg+"/foreign").Run() })
	run(t, "lvchange", "--activate", "y", "--yes", vg+"/foreign")

	foreignKey, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	formatErr := (luks.Native{}).Format(ctx, "/dev/"+vg+"/foreign", foreignKey)
	if destroyErr := foreignKey.Destroy(); destroyErr != nil {
		t.Errorf("Destroy: %v", destroyErr)
	}
	if formatErr != nil {
		t.Fatalf("formatting the foreign container: %v", formatErr)
	}
	moveDataOffset(t, "/dev/"+vg+"/foreign", foreignHeader)

	// Confirm the premise: this really is a non-default header.
	offset, err := p.luksDataOffset(ctx, p.lvPath("foreign"))
	if err != nil {
		t.Fatalf("luksDataOffset: %v", err)
	}
	if offset != foreignHeader {
		t.Fatalf("the foreign container's data offset is %d, wanted %d for this test to mean anything",
			offset, foreignHeader)
	}
	run(t, "lvchange", "--activate", "n", "--yes", vg+"/foreign")

	snapID, err := p.Snapshot(ctx, "foreign", "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.DeleteSnapshot(ctx, snapID) })

	// Restored verbatim: the volume keeps the foreign header.
	requested := int64(64<<20) - foreignHeader
	restored, err := p.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        requested,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("verbatim restore: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	// The tag records what was MEASURED, not what this package would format.
	tags := lvTags(t, vg, restored.ID)
	if !strings.Contains(tags, encryptedTagFor(foreignHeader)) {
		t.Fatalf("lv_tags = %q, want it to record the source's %d-byte header", tags, foreignHeader)
	}

	// And detached Status uses it. Assuming the default here would report
	// 12 MiB MORE than the volume can hold.
	detached, err := p.Status(ctx, restored.ID)
	if err != nil {
		t.Fatalf("Status while detached: %v", err)
	}
	if detached.SizeBytes < requested {
		t.Errorf("detached Status.SizeBytes = %d, below the %d requested", detached.SizeBytes, requested)
	}

	// The authority agrees: attach it and compare against the real mapping.
	info, err := p.Attach(ctx, restored.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, restored.ID, "test-node") })

	mapping := deviceSizeBytes(t, info.DevicePath)
	if detached.SizeBytes != mapping {
		t.Errorf("detached Status said %d; the mapping is really %d, a %d-byte error — "+
			"the recorded header size was not used", detached.SizeBytes, mapping, detached.SizeBytes-mapping)
	}
}

// TestIntegrationWrongTagIsRefusedThenRepaired drives the whole tag-authority
// loop against real LVM and a real container: a tag that disagrees with the
// container is refused while the volume is up, and an Attach — the one
// operation holding the lock — re-records it from the header and clears the
// refusal.
//
// The wrong tag is produced the way a real one would go stale: by editing it out
// of band with lvchange, which is exactly the situation the check exists for.
func TestIntegrationWrongTagIsRefusedThenRepaired(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const requested = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "drifted", SizeBytes: requested, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Baseline: the volume was tagged correctly at provision, and reports
	// usable capacity while detached.
	before, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if before.SizeBytes < requested {
		t.Fatalf("baseline detached Status.SizeBytes = %d, below the %d requested", before.SizeBytes, requested)
	}

	// Drift the tag out of band, to a header size the container does not have.
	run(t, "lvchange", "--deltag", encryptedTagFor(luksHeaderBytes),
		"--addtag", encryptedTagFor(4<<20), vg+"/"+vol.ID)
	if tags := lvTags(t, vg, vol.ID); !strings.Contains(tags, encryptedTagFor(4<<20)) {
		t.Fatalf("lv_tags = %q, want the drifted tag in place for this test to mean anything", tags)
	}

	// DETACHED, the lie is believed — there is no probe, and this is exactly
	// why a wrong tag must not be allowed to survive an attach.
	drifted, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status while detached with a drifted tag: %v", err)
	}
	if drifted.SizeBytes == before.SizeBytes {
		t.Errorf("the drifted tag changed nothing (%d); the fixture did not take", drifted.SizeBytes)
	}

	// ACTIVE, it is refused: the container's real header contradicts the tag,
	// and this is the last moment anything can see that.
	run(t, "lvchange", "--activate", "y", "--yes", vg+"/"+vol.ID)
	if _, err := p.Status(ctx, vol.ID); err == nil {
		t.Error("Status accepted a tag that disagrees with the container's own header")
	} else if !strings.Contains(err.Error(), "Attach the volume") {
		t.Errorf("error %q does not point at the repair", err)
	}
	run(t, "lvchange", "--activate", "n", "--yes", vg+"/"+vol.ID)

	// Attach repairs it, from the header rather than from an assumption.
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if tags := lvTags(t, vg, vol.ID); !strings.Contains(tags, encryptedTagFor(luksHeaderBytes)) {
		t.Fatalf("after Attach lv_tags = %q, want the tag re-recorded from the container", tags)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// And the refusal is gone, with the detached answer back to the truth.
	healed, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status after the repair: %v", err)
	}
	if healed.SizeBytes != before.SizeBytes {
		t.Errorf("after the repair Status.SizeBytes = %d, want the original %d", healed.SizeBytes, before.SizeBytes)
	}
}

// TestIntegrationResizeDoesNotDestroyTheMappingItCannotGrow is the scenario
// that motivated ErrResizeWhileAttached, run against a real dm-crypt mapping.
//
// The hazard it rules out: a resize implemented as "remove the mapping, unlock
// again" is fine until the second half fails, and then the caller — who asked
// for a bigger volume and got an error — no longer has a plaintext device at
// all. The volume is not corrupt, but nothing can read it until somebody
// notices and re-attaches, and whatever was using the device is holding a
// dangling path. That is strictly worse than the resize simply not happening,
// and the cryptsetup implementation this package migrated from did not have it,
// so shipping it would have been a regression the migration introduced.
//
// The trigger staged here is the realistic one rather than a contrived fault: a
// KeyProvider ROTATED since the volume was attached. The mapping is live and
// working — it was opened with the old key and dm-crypt does not care what the
// KeyProvider says afterwards — while the key the provider would have to unlock
// with no longer opens the container. A teardown-and-rebuild resize succeeds at
// the teardown and fails at the rebuild, every time.
//
// The assertion is not that Resize fails. It is that AFTER it fails, the
// mapping is still there and still usable.
func TestIntegrationResizeDoesNotDestroyTheMappingItCannotGrow(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	// The key the volume is created and attached with, and the one it is
	// rotated to. Only the first opens the container.
	rotated := false
	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
			passphrase := "the-original-passphrase"
			if rotated {
				passphrase = "a-passphrase-that-opens-nothing"
			}
			return enclave.NewMemoryEnclave([]byte(passphrase))
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "live", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("still here"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The key moves out from under the live attachment.
	rotated = true

	if err := p.Resize(ctx, vol.ID, 128<<20); !errors.Is(err, ErrResizeWhileAttached) {
		t.Fatalf("Resize while attached = %v, want ErrResizeWhileAttached", err)
	}

	// THE assertion. Everything below this line would fail against a resize
	// that tore the mapping down before finding out it could not rebuild it.
	if _, err := dmcrypt.Lookup(ctx, p.mappingName(vol.ID)); err != nil {
		t.Fatal("the plaintext mapping is gone after a refused resize; the resize destroyed " +
			"a working mapping it was never able to replace")
	}
	if _, err := os.Stat(info.DevicePath); err != nil {
		t.Fatalf("the plaintext device %s is gone after a refused resize: %v", info.DevicePath, err)
	}
	got, err := os.ReadFile(filepath.Join(target, "payload"))
	if err != nil {
		t.Fatalf("the mounted filesystem did not survive a refused resize: %v", err)
	}
	if string(got) != "still here" {
		t.Errorf("contents = %q, want them untouched by a refused resize", got)
	}

	// And the volume is still fully usable: the mapping was never disturbed, so
	// writing to it works exactly as it did before.
	if err := os.WriteFile(filepath.Join(target, "after"), []byte("written after"), 0o600); err != nil {
		t.Fatalf("writing after a refused resize: %v", err)
	}
}

// TestIntegrationBlockDeviceOperations drives internal/blkdev against a real
// logical volume, which is the only place its two remaining operations can be
// checked at all.
//
// Both need a block device opened for writing, so a unit test can reach their
// refusals and nothing else: BLKGETSIZE64 and BLKZEROOUT are answered by a
// driver, and a regular file's driver answers ENOTTY. What is proved here is
// what the callers depend on and what the weaker ioctl would not have given
// them — that after the call, the bytes that were there are zeroes, rather than
// a range the device is free to remember.
func TestIntegrationBlockDeviceOperations(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 32 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "scratch", SizeBytes: size})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	// Size reads the driver rather than seeking, so it reports at least the
	// capacity that was asked for.
	got, err := blkdev.Size(info.DevicePath)
	if err != nil {
		t.Fatalf("Size(%s): %v", info.DevicePath, err)
	}
	if got < size {
		t.Errorf("Size = %d, want at least the %d that was provisioned", got, size)
	}

	const marker = "SENSITIVE-TENANT-DATA"
	writeMarker(t, info.DevicePath, marker)
	if !markerPresent(t, info.DevicePath, marker) {
		t.Fatal("the marker did not reach the device; the rest of this test would prove nothing")
	}

	// From an offset, so the range arithmetic is exercised rather than the
	// whole-device case alone. The marker sits past it.
	if err := blkdev.ZeroOut(ctx, info.DevicePath, markerOffset-(4<<20)); err != nil {
		t.Fatalf("ZeroOut: %v", err)
	}
	if markerPresent(t, info.DevicePath, marker) {
		t.Error("the marker survived the zeroing")
	}

	// A caller that has given up is told so rather than having a real device
	// written on its behalf. (This is the check before the ioctl; the one after
	// it — for a caller that gave up while the uninterruptible ioctl was
	// running — cannot be reached without racing the kernel, and is left to the
	// seam-level test in pkg/drbd, which cancels mid-wipe through the fake.)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := blkdev.ZeroOut(canceled, info.DevicePath, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("ZeroOut under a canceled context = %v, want context.Canceled", err)
	}

	// The end of the device is nothing to do rather than an error, and past it
	// is a refusal: a caller that computed an offset from the wrong size must
	// not have it silently accepted.
	if err := blkdev.ZeroOut(ctx, info.DevicePath, got); err != nil {
		t.Errorf("ZeroOut at the end of the device = %v, want nil", err)
	}
	if err := blkdev.ZeroOut(ctx, info.DevicePath, got+1); !errors.Is(err, blkdev.ErrOffsetPastEnd) {
		t.Errorf("ZeroOut past the end = %v, want ErrOffsetPastEnd", err)
	}
}

// TestIntegrationCopyMovesAWholeDevice covers the other half of the conversion:
// the copy that used to be dd. A regular file exercises the loop, but only a
// device proves the copy is whole-device and flushed — the property a restore
// depends on when the volume is detached immediately afterwards.
func TestIntegrationCopyMovesAWholeDevice(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 32 << 20
	src, err := p.Provision(ctx, common.VolumeSpec{Name: "source", SizeBytes: size})
	if err != nil {
		t.Fatalf("Provision the source: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, src.ID) })
	dst, err := p.Provision(ctx, common.VolumeSpec{Name: "destination", SizeBytes: size})
	if err != nil {
		t.Fatalf("Provision the destination: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, dst.ID) })

	srcInfo, err := p.Attach(ctx, src.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach the source: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, src.ID, "test-node") })
	dstInfo, err := p.Attach(ctx, dst.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach the destination: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, dst.ID, "test-node") })

	const marker = "COPIED-CONTENT"
	writeMarker(t, srcInfo.DevicePath, marker)

	if err := blkdev.Copy(ctx, srcInfo.DevicePath, dstInfo.DevicePath); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !markerPresent(t, dstInfo.DevicePath, marker) {
		t.Error("the copy did not carry the source's content to the destination")
	}
}

// TestIntegrationMountTableIdentifiesTheDeviceByNumber is the round trip that
// decides whether any mount lookup finds anything, checked where it can be:
// against a real logical volume this test built.
//
// It cannot live in the unit suite, which runs in a container on CI — a
// container has a mount table and no device nodes to stat, so a test needing
// one fails there while passing on a workstation. The detail it pins would
// otherwise be found by nobody: /proc/self/mountinfo prints major:minor in
// DECIMAL, while the obvious way to obtain the same pair for comparison —
// stat's %t:%T — prints hex. Read one as the other and every mount lookup
// silently matches nothing, which this provider reports as "not mounted" and
// acts on by destroying a volume.
func TestIntegrationMountTableIdentifiesTheDeviceByNumber(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	target := t.TempDir()
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })

	// The name this provider spells is a symlink to the /dev/dm-N that carries
	// the number; the number is what the table records.
	device := p.lvPath(vol.ID)
	major, minor, err := mountinfo.DeviceNumber(device)
	if err != nil {
		t.Fatalf("DeviceNumber(%s): %v", device, err)
	}

	entries, err := mountinfo.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entry, ok := mountinfo.EntryAt(entries, target)
	if !ok {
		t.Fatalf("the mount table has no entry for %q", target)
	}
	if entry.Major != major || entry.Minor != minor {
		t.Errorf("stat says %d:%d, the mount table says %d:%d — one of them is being read in the wrong base",
			major, minor, entry.Major, entry.Minor)
	}

	// And the seam the provider actually uses finds the mount from the device
	// name, whichever of the device's names it was given.
	for _, name := range []string{device, "/dev/mapper/" + vg + "-" + string(vol.ID)} {
		targets, err := (mountinfo.System{}).MountPointsFor(ctx, name)
		if err != nil {
			t.Fatalf("MountPointsFor(%s): %v", name, err)
		}
		if !contains(targets, target) {
			t.Errorf("MountPointsFor(%s) = %v, want it to include %q", name, targets, target)
		}
	}
}

// TestIntegrationMountPropagationGuard drives the propagation guard against the
// real kernel, in both directions, because a guard is only as good as the two
// answers it gives: it must refuse a mount the workload could not see, and it
// must NOT refuse one it could.
//
// Neither half is reachable without root and a real mount. Propagation is
// inherited from the parent at the moment mount(2) is called, so producing a
// shared mount means making a parent shared first — which is exactly the
// operator action the finding's remedy tells somebody to perform, exercised
// here rather than described.
func TestIntegrationMountPropagationGuard(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup:      vg,
		NodeID:           "test-node",
		MountPropagation: MountPropagationShared,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	// A tmpfs of our own to be the parent, so the test never changes the
	// propagation of anything on the host that it did not create.
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := unix.Mount("none", parent, "tmpfs", 0, ""); err != nil {
		t.Fatalf("mounting the parent tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(parent, unix.UMOUNT_NOFOLLOW) })

	target := filepath.Join(parent, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	t.Run("a private parent is refused, and the mount is unwound", func(t *testing.T) {
		if err := unix.Mount("", parent, "", unix.MS_PRIVATE, ""); err != nil {
			t.Fatalf("making the parent private: %v", err)
		}

		err := p.Mount(ctx, vol.ID, target, common.MountOptions{})
		if err == nil {
			_ = p.Unmount(ctx, vol.ID, target)
			t.Fatal("Mount accepted a mount under a private parent")
		}
		if !errors.Is(err, preflight.ErrMountNotPropagated) {
			t.Fatalf("Mount = %v, want ErrMountNotPropagated", err)
		}
		if !strings.Contains(err.Error(), "private") {
			t.Errorf("the finding does not say what the mount actually is: %v", err)
		}

		// And nothing is left mounted: the caller was told the operation
		// failed, and a mount it does not know about is one nothing unmounts.
		entries, loadErr := mountinfo.Load()
		if loadErr != nil {
			t.Fatalf("Load: %v", loadErr)
		}
		if _, mounted := mountinfo.EntryAt(entries, target); mounted {
			t.Error("a refused mount was left mounted")
		}
	})

	t.Run("an unmounted path is refused rather than answered", func(t *testing.T) {
		// The fail-closed half, which needs a real block device to ask ABOUT
		// and so cannot live in the unit suite: CI runs that in a container,
		// and a container has no device node to name. "Nothing is mounted
		// there" is not an answer about propagation, and a guard reading it as
		// one would pass the case where the mount is missing entirely.
		_, _, _, err := (mountinfo.System{}).PropagationOf(ctx, p.lvPath(vol.ID), filepath.Join(t.TempDir(), "nowhere"))
		if !errors.Is(err, mountinfo.ErrNotMounted) {
			t.Fatalf("PropagationOf of an unmounted path = %v, want ErrNotMounted", err)
		}
	})

	t.Run("a symlinked target never reaches the guard", func(t *testing.T) {
		// The guard looks the target up in the kernel's table by the string it
		// was given, which would be wrong if mount(2) could resolve that string
		// to some other path. It cannot: the mounter pins the target with
		// openat2 under RESOLVE_NO_SYMLINKS, so a symlink at the final
		// component or at any parent is refused before anything is mounted.
		// This pins the ORDERING — the refusal is the mounter's, not the
		// guard's, and no mount is left behind for the guard to judge.
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		err := p.Mount(ctx, vol.ID, link, common.MountOptions{})
		if err == nil {
			_ = p.Unmount(ctx, vol.ID, link)
			t.Fatal("Mount followed a symlinked target")
		}
		// The mounter's refusal, not a propagation finding: the guard never ran.
		if errors.Is(err, preflight.ErrMountNotPropagated) || errors.Is(err, preflight.ErrIndeterminate) {
			t.Errorf("the propagation guard judged a mount that was never made: %v", err)
		}

		entries, loadErr := mountinfo.Load()
		if loadErr != nil {
			t.Fatalf("Load: %v", loadErr)
		}
		if _, mounted := mountinfo.EntryAt(entries, target); mounted {
			t.Error("a refused symlinked target left something mounted")
		}
	})

	t.Run("a shared parent is accepted", func(t *testing.T) {
		// This is the remedy the finding above prints, performed.
		if err := unix.Mount("", parent, "", unix.MS_SHARED, ""); err != nil {
			t.Fatalf("making the parent shared: %v", err)
		}

		if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
			t.Fatalf("Mount under a shared parent = %v, want nil", err)
		}
		t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })

		// The kernel agrees the mount propagates, which is the property the
		// guard passed it on.
		id, propagates, spelling, err := (mountinfo.System{}).PropagationOf(ctx, p.lvPath(vol.ID), target)
		if err != nil {
			t.Fatalf("PropagationOf: %v", err)
		}
		if !propagates {
			t.Errorf("the accepted mount is %q, which does not propagate", spelling)
		}
		// And the kernel hands back an identity for the mount instance, which
		// is what tells this mount from a second mount of the same device at
		// the same path — the thing (device, path) cannot distinguish.
		if id == 0 {
			t.Error("the mount has no identity, so a rollback could not tell it from a restacked one")
		}
	})
}

// TestIntegrationOrphanReaper drives the inspection against a real LUKS
// container and a real device-mapper mapping, which is the only place the
// identity proof can be checked: it reads /dev and /sys, and the mapping it
// judges was made by a real unlock.
//
// The boot that "ended" is supplied rather than waited for — a test cannot
// reboot the host — but everything else is real: a real volume, a real mapping,
// and a real record written on it before the mapping existed.
//
// Nothing here removes anything, because the code no longer can. What is
// verified is that each verdict is reached correctly against real state, and
// that every one of them leaves the mapping exactly where it was.
func TestIntegrationOrphanReaper(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	const priorBoot = "00000000-0000-0000-0000-0000deadbeef"
	base := Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "correct-horse-battery-staple"),
	}

	live, err := New(base)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := live.Provision(ctx, common.VolumeSpec{Name: "secrets", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = live.Delete(ctx, vol.ID) })

	info, err := live.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = live.Detach(ctx, vol.ID, "test-node") })
	if !strings.HasPrefix(info.DevicePath, "/dev/mapper/") {
		t.Fatalf("DevicePath = %q, want a plaintext mapping", info.DevicePath)
	}

	inspect := func(t *testing.T, p *Provider) MappingFinding {
		t.Helper()
		findings, err := p.InspectMappings(ctx)
		if err != nil {
			t.Fatalf("InspectMappings: %v", err)
		}
		return onlyFinding(t, findings)
	}

	// The attach wrote the record before it created the mapping, which is what
	// makes any verdict possible at all.
	t.Run("this boot's mapping is live", func(t *testing.T) {
		if v := inspect(t, live).Verdict; v != VerdictLive {
			t.Fatalf("verdict = %q, want %q", v, VerdictLive)
		}
	})

	t.Run("another node sees it as that node's, not as an orphan", func(t *testing.T) {
		// Same volume, same record, a provider that believes it is a different
		// node — the shared-storage case. Keying on the boot alone would call
		// this orphaned, because another node's boot never matches this one's.
		elsewhere := base
		elsewhere.NodeID = "some-other-node"
		elsewhere.bootID = func() (string, error) { return priorBoot, nil }
		p, err := New(elsewhere)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := inspect(t, p).Verdict; v != VerdictForeignNode {
			t.Fatalf("verdict = %q, want %q", v, VerdictForeignNode)
		}
	})

	t.Run("a mapping from an ended boot is reported, and left alone", func(t *testing.T) {
		rebooted := base
		rebooted.bootID = func() (string, error) { return priorBoot, nil }
		p, err := New(rebooted)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := inspect(t, p).Verdict; v != VerdictOrphaned {
			t.Fatalf("verdict = %q, want %q", v, VerdictOrphaned)
		}
	})

	// Whatever was concluded, the real mapping is still there. This is the
	// property that makes the whole thing safe to run anywhere.
	if _, err := os.Stat(info.DevicePath); err != nil {
		t.Errorf("the inspection removed a live mapping: %v", err)
	}
}

func onlyFinding(t *testing.T, findings []MappingFinding) MappingFinding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one: %+v", len(findings), findings)
	}
	return findings[0]
}

// TestIntegrationKeyFileContainment drives the key-path guard against a real
// mounted volume, which is the shape the exposure actually takes: the volume is
// mounted, somebody puts the key file inside it because that is the convenient
// place, and everything works — the volume unlocks and the credential is now in
// the workload's filesystem.
func TestIntegrationKeyFileContainment(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	keys := filepath.Join(t.TempDir(), "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	outside := filepath.Join(keys, "volume.key")
	if err := os.WriteFile(outside, []byte("correct-horse-battery-staple"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	build := func(t *testing.T, keyFile string) *Provider {
		t.Helper()
		p, err := NewFromSettings(map[string]string{
			SettingVolumeGroup: vg,
			SettingNodeID:      "test-node",
			SettingEncrypted:   "true",
			SettingLUKSKeyFile: keyFile,
		})
		if err != nil {
			t.Fatalf("NewFromSettings: %v", err)
		}
		return p
	}

	p := build(t, outside)
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secrets", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	target := t.TempDir()
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount with the key file outside = %v, want nil", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })

	t.Run("a key file inside the mounted volume is refused", func(t *testing.T) {
		// Written into the volume itself, through the live mount — exactly what
		// somebody does when the shared volume looks like a good place for it.
		inside := filepath.Join(target, "volume.key")
		if err := os.WriteFile(inside, []byte("correct-horse-battery-staple"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		exposed := build(t, inside)
		err := exposed.Mount(ctx, vol.ID, target, common.MountOptions{})
		if !errors.Is(err, ErrKeyFileInsideVolume) {
			t.Fatalf("Mount = %v, want ErrKeyFileInsideVolume", err)
		}

		// And the unlock path refuses it too, from the other side: the volume is
		// already mounted and the key is inside that mount.
		if _, err := exposed.Attach(ctx, vol.ID, "test-node"); !errors.Is(err, ErrKeyFileInsideVolume) {
			t.Errorf("Attach = %v, want the unlock refused as well", err)
		}
	})

	t.Run("the volume's own file at the key's path is refused on a FIRST mount", func(t *testing.T) {
		// The case the existing-mounts check structurally cannot see, because
		// on a first mount the volume has no mount points to inspect.
		//
		// The volume already contains a file called "planted.key". A host file
		// of the same name sits in the directory it is about to be mounted on,
		// and that host file is what the configuration names. After the mount
		// that path would resolve to the VOLUME's file — so the provider's key
		// would be a file inside the volume it just handed over.
		staging := t.TempDir()
		if err := p.Mount(ctx, vol.ID, staging, common.MountOptions{}); err != nil {
			t.Fatalf("Mount for staging: %v", err)
		}
		planted := filepath.Join(staging, "planted.key")
		if err := os.WriteFile(planted, []byte("attacker-controlled"), 0o600); err != nil {
			t.Fatalf("WriteFile into the volume: %v", err)
		}
		if err := p.Unmount(ctx, vol.ID, staging); err != nil {
			t.Fatalf("Unmount: %v", err)
		}

		fresh := t.TempDir()
		hostKey := filepath.Join(fresh, "planted.key")
		if err := os.WriteFile(hostKey, []byte("correct-horse-battery-staple"), 0o600); err != nil {
			t.Fatalf("WriteFile on the host: %v", err)
		}
		// Before the mount this path is the host's key; the fixture is only
		// meaningful if that is true.
		if got, _ := os.ReadFile(hostKey); string(got) != "correct-horse-battery-staple" {
			t.Fatalf("the host key is not what the configuration names: %q", got)
		}

		err := build(t, hostKey).Mount(ctx, vol.ID, fresh, common.MountOptions{})
		if !errors.Is(err, ErrKeyFileInsideVolume) {
			t.Fatalf("Mount = %v, want the first mount refused", err)
		}
		// And nothing was mounted, so the volume's file never became the
		// provider's key even briefly.
		entries, loadErr := mountinfo.Load()
		if loadErr != nil {
			t.Fatalf("Load: %v", loadErr)
		}
		if _, mounted := mountinfo.EntryAt(entries, fresh); mounted {
			t.Error("the refused mount happened anyway")
		}
	})

	t.Run("a symlink into the volume is refused", func(t *testing.T) {
		inside := filepath.Join(target, "real.key")
		if err := os.WriteFile(inside, []byte("correct-horse-battery-staple"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(keys, "looks-fine.key")
		if err := os.Symlink(inside, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		err := build(t, link).Mount(ctx, vol.ID, target, common.MountOptions{})
		if !errors.Is(err, ErrKeyFileInsideVolume) {
			t.Fatalf("Mount = %v, want the symlinked key file refused", err)
		}
		if !strings.Contains(err.Error(), inside) {
			t.Errorf("the refusal does not name where the key really is: %v", err)
		}
	})
}
