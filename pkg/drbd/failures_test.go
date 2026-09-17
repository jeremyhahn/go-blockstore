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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/blkdev"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// A provider that swallows a failed drbdadm or lvs reports success for work
// that did not happen, which on a replication path means an HA controller
// acting on a volume that is not in the state it was told about. This walks
// every system command every method runs, fails exactly one of them, and
// requires the method to fail and to say what broke.
func TestSystemCommandFailuresSurface(t *testing.T) {
	const dev = "/dev/drbd0"

	// baseline scripts every command a method runs successfully; each case then
	// re-scripts one of them to fail, since re-scripting an argv replaces it.
	baseline := func(r *fakeRunner) {
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.scriptLVS(lvsJSON(lvEntry{
			Name: testVolume, VG: testVG,
			Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
		}))
		r.on(binDRBDAdm, "up", testVolume).returns("")
		r.on(binDRBDAdm, "down", testVolume).returns("")
		r.on(binDRBDAdm, "secondary", testVolume).returns("")
		r.on(binDRBDAdm, "resize", testVolume).returns("")
		r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(testSize*2, false), 10)+"b", "vg0/vol1").returns("")
		r.on(binLVRemove, "--force", "vg0/vol1").returns("")
		r.on(binLVRemove, "--force", "vg0/vol1.snap.nightly").returns("")
		r.on(binLVCreate, "--yes", "--snapshot", "--name", "vol1.snap.nightly",
			"--extents", "20%ORIGIN", "vg0/vol1").returns("")
		r.on(binBlkid, "-p", "-o", "export", dev).returns("TYPE=ext4\n")
		r.on(binResize2fs, dev).returns("")
		r.scriptMount(dev, testMountPoint)
	}

	// The lvs report a snapshot case needs: the origin plus its snapshot.
	withSnapshot := func(r *fakeRunner) {
		r.scriptLVS(lvsJSON(
			lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)},
			lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: testVolume},
		))
	}

	statusFails := func(r *fakeRunner) { r.on(binDRBDSetup, "status", "--json").fails(20, "drbdsetup: no such module") }
	lvsFails := func(r *fakeRunner) {
		r.on(binLVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", lvsFields, testVG).
			fails(5, "Volume group \"vg0\" not found")
	}

	tests := []struct {
		name string
		// breakIt re-scripts one command to fail.
		breakIt func(*fakeRunner)
		call    func(*Provider) error
		wantIn  string
	}{
		{
			"Attach: drbdadm up", func(r *fakeRunner) {
				// Attach converges when the resource is already up, which the
				// baseline says it is, so the case that reaches drbdadm up at
				// all is the one where it is down.
				r.scriptStatus(emptyStatus)
				r.on(binDRBDAdm, "up", testVolume).fails(1, "no resources defined")
			},
			func(p *Provider) error { _, err := p.Attach(context.Background(), testVolume, testNode); return err },
			"vol1",
		},
		{
			"Attach: drbdsetup status", statusFails,
			func(p *Provider) error { _, err := p.Attach(context.Background(), testVolume, testNode); return err },
			"drbd status",
		},
		{
			"Detach: drbdsetup status", statusFails,
			func(p *Provider) error { return p.Detach(context.Background(), testVolume, testNode) },
			"drbd status",
		},
		{
			"Detach: drbdadm down", func(r *fakeRunner) {
				r.scriptStatus(secondaryStatus(testVolume, 0))
				r.on(binDRBDAdm, "down", testVolume).fails(1, "device is held open")
			},
			func(p *Provider) error { return p.Detach(context.Background(), testVolume, testNode) },
			"vol1",
		},
		{
			"Mount: drbdsetup status", statusFails,
			func(p *Provider) error {
				return p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
			},
			"drbd status",
		},
		{
			"Mount: blkid", func(r *fakeRunner) { r.on(binBlkid, "-p", "-o", "export", dev).fails(4, "cannot open") },
			func(p *Provider) error {
				return p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
			},
			dev,
		},
		{
			"Mount: mkfs", func(r *fakeRunner) {
				r.on(binBlkid, "-p", "-o", "export", dev).fails(blkidNoSig, "")
				r.on("mkfs.ext4", "-q", dev).fails(1, "mkfs.ext4: Device busy")
			},
			func(p *Provider) error {
				return p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
			},
			"ext4",
		},
		{
			"Resize: lvs", lvsFails,
			func(p *Provider) error { return p.Resize(context.Background(), testVolume, testSize*2) },
			"vg0",
		},
		{
			"Resize: lvextend", func(r *fakeRunner) {
				r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(testSize*2, false), 10)+"b", "vg0/vol1").
					fails(5, "insufficient free space")
			},
			func(p *Provider) error { return p.Resize(context.Background(), testVolume, testSize*2) },
			"vg0/vol1",
		},
		{
			"Resize: drbdadm resize", func(r *fakeRunner) {
				r.on(binDRBDAdm, "resize", testVolume).fails(1, "peer has not resized yet")
			},
			func(p *Provider) error { return p.Resize(context.Background(), testVolume, testSize*2) },
			"vol1",
		},
		{
			"Snapshot: drbdsetup status", statusFails,
			func(p *Provider) error { _, err := p.Snapshot(context.Background(), testVolume, "nightly"); return err },
			"drbd status",
		},
		{
			"Snapshot: lvs", lvsFails,
			func(p *Provider) error { _, err := p.Snapshot(context.Background(), testVolume, "nightly"); return err },
			"vg0",
		},
		{
			"Snapshot: lvcreate", func(r *fakeRunner) {
				r.on(binLVCreate, "--yes", "--snapshot", "--name", "vol1.snap.nightly",
					"--extents", "20%ORIGIN", "vg0/vol1").fails(5, "snapshot origin is busy")
			},
			func(p *Provider) error { _, err := p.Snapshot(context.Background(), testVolume, "nightly"); return err },
			"vol1",
		},
		{
			"ListSnapshots: lvs", lvsFails,
			func(p *Provider) error { _, err := p.ListSnapshots(context.Background(), testVolume); return err },
			"vg0",
		},
		{
			"DeleteSnapshot: lvs", lvsFails,
			func(p *Provider) error { return p.DeleteSnapshot(context.Background(), "vg0/vol1.snap.nightly") },
			"vg0",
		},
		{
			"DeleteSnapshot: lvremove", func(r *fakeRunner) {
				withSnapshot(r)
				r.on(binLVRemove, "--force", "vg0/vol1.snap.nightly").fails(5, "logical volume is in use")
			},
			func(p *Provider) error { return p.DeleteSnapshot(context.Background(), "vg0/vol1.snap.nightly") },
			"vol1.snap.nightly",
		},
		{
			"Delete: drbdsetup status", statusFails,
			func(p *Provider) error { return p.Delete(context.Background(), testVolume) },
			"drbd status",
		},
		{
			"Delete: lvs", func(r *fakeRunner) {
				r.scriptStatus(secondaryStatus(testVolume, 0))
				lvsFails(r)
			},
			func(p *Provider) error { return p.Delete(context.Background(), testVolume) },
			"vg0",
		},
		{
			"Delete: drbdadm down", func(r *fakeRunner) {
				r.scriptStatus(secondaryStatus(testVolume, 0))
				r.on(binDRBDAdm, "down", testVolume).fails(1, "device is held open")
			},
			func(p *Provider) error { return p.Delete(context.Background(), testVolume) },
			"vol1",
		},
		{
			"Delete: lvremove", func(r *fakeRunner) {
				r.scriptStatus(secondaryStatus(testVolume, 0))
				r.on(binLVRemove, "--force", "vg0/vol1").fails(5, "logical volume is in use")
			},
			func(p *Provider) error { return p.Delete(context.Background(), testVolume) },
			"vg0/vol1",
		},
		{
			"Status: drbdsetup status", statusFails,
			func(p *Provider) error { _, err := p.Status(context.Background(), testVolume); return err },
			"drbd status",
		},
		{
			"Demote: drbdadm secondary", func(r *fakeRunner) {
				r.on(binDRBDAdm, "secondary", testVolume).fails(11, "device is held open")
			},
			func(p *Provider) error { return p.Demote(context.Background(), testVolume) },
			"vol1",
		},
		{
			"ReplicationState: drbdsetup status", statusFails,
			func(p *Provider) error { _, err := p.ReplicationState(context.Background(), testVolume); return err },
			"drbd status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			baseline(r)
			tc.breakIt(r)

			err := tc.call(p)
			if err == nil {
				t.Fatalf("%s succeeded despite the command failing", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not mention %q", err, tc.wantIn)
			}
			// The failure has to reach the caller as the command failure it
			// was, not flattened into a sentinel that means something else.
			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Errorf("error does not carry the *CommandError: %v", err)
			}
		})
	}
}

// TestMountTableFailuresFailClosed is the sweep above's counterpart for the one
// lookup that is no longer a command.
//
// A mount table that could not be read must never be reported as "not mounted".
// That confusion is what asking findmnt made unavoidable — its single non-zero
// exit meant both — and "not mounted" is what Unmount converges on and what
// Status presents as a volume nobody is using.
func TestMountTableFailuresFailClosed(t *testing.T) {
	cases := map[string]error{
		"unreadable proc file": &mountinfo.ReadError{Path: mountinfo.ProcPath, Err: os.ErrPermission},
		"malformed record": &mountinfo.ParseError{
			Line: 12, Text: "1 2 8:1 /", Err: mountinfo.ErrTooFewFields,
		},
		"device not identifiable": &mountinfo.DeviceError{
			Path: "/dev/drbd0", Err: mountinfo.ErrNotBlockDevice,
		},
	}

	calls := map[string]struct {
		call   func(*Provider) error
		wantIn string
	}{
		"Unmount": {
			call: func(p *Provider) error { return p.Unmount(context.Background(), testVolume, testMountPoint) },
			// Unmount asks where the DEVICE is mounted, not what is mounted at
			// the path, so the device is what its failure names.
			wantIn: "/dev/drbd0",
		},
		"Status": {
			call:   func(p *Provider) error { _, err := p.Status(context.Background(), testVolume); return err },
			wantIn: "/dev/drbd0",
		},
	}

	for name, tableErr := range cases {
		for method, tc := range calls {
			t.Run(method+"/"+name, func(t *testing.T) {
				p, r := newTestProvider(t)
				provision(t, p, r, defaultSpec())
				r.reset()

				r.scriptStatus(primaryStatus(testVolume, 0))
				r.failMountTable(tableErr)

				err := tc.call(p)
				if err == nil {
					t.Fatalf("%s succeeded over a mount table it could not read", method)
				}
				if !errors.Is(err, tableErr) {
					t.Errorf("%s = %v, want it to carry the mount-table failure", method, err)
				}
				if !strings.Contains(err.Error(), tc.wantIn) {
					t.Errorf("error %q does not say what was being looked up", err)
				}
			})
		}
	}
}

// TestNewRejectsUnusableDirectories covers construction against a path that
// cannot become a directory. A file where a directory belongs fails MkdirAll
// for root and non-root alike, which a permission bit would not.
func TestNewRejectsUnusableDirectories(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("writing blocker: %v", err)
	}

	for _, key := range []string{SettingConfigDir, SettingStateDir} {
		t.Run(key, func(t *testing.T) {
			settings := testSettings(t)
			settings[key] = filepath.Join(blocker, "sub")

			_, err := New(settings, WithRunner(newFakeRunner(t)), WithSecretProvider(testSecretProvider))
			if err == nil {
				t.Fatalf("New succeeded with %s under a regular file", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name the setting %q", err, key)
			}
		})
	}
}

func TestNewRejectsANilRunner(t *testing.T) {
	_, err := New(testSettings(t), WithRunner(nil), WithSecretProvider(testSecretProvider))
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with a nil runner = %v, want common.ErrInvalidArgument", err)
	}
}

// TestStateDirectoryFailuresSurface covers the other half of the persistence
// path: a state directory that stops being a directory under the provider.
func TestStateDirectoryFailuresSurface(t *testing.T) {
	p, r := newTestProvider(t)
	stateDir := p.Config().StateDir

	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatalf("removing state dir: %v", err)
	}
	if err := os.WriteFile(stateDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("replacing state dir with a file: %v", err)
	}

	// Provisioning cannot even check whether the name is taken.
	if _, err := p.Provision(context.Background(), *defaultSpec()); err == nil {
		t.Error("Provision succeeded with an unusable state directory")
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("Provision ran commands before its state was readable: %v", got)
	}
	// And listing reports the failure rather than an empty tree, which would
	// hand the allocator a clean slate over volumes that still exist.
	if _, err := p.listMeta(); err == nil {
		t.Error("listMeta succeeded with an unusable state directory")
	}
}

// TestDeleteRejectsAHostileVolumeID covers the validation on Delete's path,
// which reads past the completeness mark and so does not share lookup's.
func TestDeleteRejectsAHostileVolumeID(t *testing.T) {
	p, r := newTestProvider(t)
	for _, id := range []string{"../../etc/passwd", "vol1; rm -rf /", "all", ""} {
		if err := p.Delete(context.Background(), id); !errors.Is(err, common.ErrNotFound) {
			t.Errorf("Delete(%q) = %v, want ErrNotFound", id, err)
		}
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a hostile volume id ran commands: %v", got)
	}
}

// TestRestoreCopyFailureRollsBack covers the copy in the restore path: a copy
// that fails must unwind the volume it was filling, not leave a backing device
// holding half a filesystem.
func TestRestoreCopyFailureRollsBack(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, &common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 2})
	r.reset()

	const snapLV = "vol1.snap.nightly"
	r.scriptLVS(lvsJSON(lvEntry{
		Name: snapLV, VG: testVG, Origin: testVolume,
		OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.scriptProvisionAt("vol2", originBacking())
	r.failCopy(&blkdev.CopyError{
		Source:      "/dev/vg0/" + snapLV,
		Destination: "/dev/vg0/vol2",
		Op:          "copying",
		Err:         errors.New("input/output error"),
	})
	r.on(binLVRemove, "--force", "vg0/vol2").returns("")

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: testSize, Replicas: 2,
		SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
	})
	if err == nil {
		t.Fatal("Provision succeeded despite the copy failing")
	}
	if !strings.Contains(err.Error(), "vol2") {
		t.Errorf("error %q does not name the destination", err)
	}
	r.assertRan(t, "lvremove --force vg0/vol2")
	// Nothing got as far as DRBD, so no metadata was written over the copy.
	r.assertNotRan(t, "create-md")
	if _, err := p.loadMeta("vol2"); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("a failed restore left a state record: %v", err)
	}
}

func TestFilesystemGrowFailureOnXFS(t *testing.T) {
	p, r := newTestProvider(t)
	spec := defaultSpec()
	spec.FSType = "xfs"
	provision(t, p, r, spec)
	r.reset()

	// Resize refuses a resource that is down, so this one is up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	newSize := testSize * 2
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", testMountPoint)
	r.on(binXFSGrowfs, testMountPoint).fails(1, "xfs_growfs: XFS_IOC_FSGROWFSDATA failed")

	err := p.Resize(context.Background(), testVolume, newSize)
	if err == nil {
		t.Fatal("Resize succeeded despite xfs_growfs failing")
	}
	if !strings.Contains(err.Error(), testMountPoint) {
		t.Errorf("error %q does not name the mount point", err)
	}
}

// TestFilesystemGrowRejectsAnUnknownType proves the guard on the grow switch
// fires. It is unreachable through the API — FSType passed the allowlist at
// provision time — but a third filesystem added to that allowlist without a
// grow here would otherwise leave every resize silently short.
func TestFilesystemGrowRejectsAnUnknownType(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	meta.FSType = "btrfs"

	r.scriptMount("/dev/drbd0", testMountPoint)
	_, err = p.growFilesystem(context.Background(), &meta)
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("growFilesystem of an unknown type = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "btrfs") {
		t.Errorf("error %q does not name the filesystem", err)
	}
}

// TestMalformedToolOutputSurfaces requires a parse failure to be an error. A
// tool whose output this package cannot read is not a tool reporting "nothing
// here", and treating it as one would read an unparseable status as "no
// resources up" and an unreadable mount table as "not mounted".
func TestMalformedToolOutputSurfaces(t *testing.T) {
	tests := []struct {
		name   string
		script func(*fakeRunner)
		call   func(*Provider) error
		wantIn string
	}{
		{
			"drbdsetup status", func(r *fakeRunner) { r.scriptStatus(`{"not":"an array"}`) },
			func(p *Provider) error { _, err := p.ReplicationState(context.Background(), testVolume); return err },
			"drbdsetup",
		},
		{
			"lvs report", func(r *fakeRunner) {
				r.on(binLVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", lvsFields, testVG).
					returns("not json at all")
			},
			func(p *Provider) error { _, err := p.ListSnapshots(context.Background(), testVolume); return err },
			"lvs report",
		},
		{
			"mount table by mountpoint", func(r *fakeRunner) {
				r.failMountTable(&mountinfo.ParseError{
					Line: 12, Text: "1 2 8:1 /", Err: mountinfo.ErrTooFewFields,
				})
			},
			func(p *Provider) error { return p.Unmount(context.Background(), testVolume, testMountPoint) },
			"mountinfo",
		},
		{
			"mount table by source", func(r *fakeRunner) {
				r.scriptStatus(primaryStatus(testVolume, 0))
				r.failMountTable(&mountinfo.ParseError{
					Line: 12, Text: "1 2 8:1 /", Err: mountinfo.ErrTooFewFields,
				})
			},
			func(p *Provider) error { _, err := p.Status(context.Background(), testVolume); return err },
			"mountinfo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()
			tc.script(r)

			err := tc.call(p)
			if err == nil {
				t.Fatalf("%s: unreadable output was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestParseSnapshotIDRejectsNamesWeCouldNotHaveMade covers the validation after
// the split: an id can decompose cleanly and still name halves this provider
// would never have created.
func TestParseSnapshotIDRejectsNamesWeCouldNotHaveMade(t *testing.T) {
	p, _ := newTestProvider(t)
	for _, id := range []string{
		"vg0/VOL1.snap.nightly", // uppercase volume
		"vg0/vol1.snap.NIGHTLY", // uppercase snapshot
		"vg0/-rf.snap.nightly",  // a volume half that would read as an option
		"vg0/all.snap.nightly",  // drbdadm's every-resource keyword
	} {
		if _, _, err := p.parseSnapshotID(id); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("parseSnapshotID(%q) = %v, want common.ErrInvalidArgument", id, err)
		}
	}
}

// TestMountAndUnmountFailuresSurface is what the command sweep above cannot
// cover any more: mounting does not go through the runner, so its failures
// arrive from the Mounter rather than as a *CommandError.
func TestMountAndUnmountFailuresSurface(t *testing.T) {
	t.Run("mount", func(t *testing.T) {
		p, r, m := newTestProviderWithMounter(t)
		provision(t, p, r, defaultSpec())
		r.reset()

		r.scriptStatus(primaryStatus(testVolume, 0))
		r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")
		m.FailMount(errors.New("mounting /dev/drbd0: no such device"))

		err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
		if err == nil {
			t.Fatal("Mount succeeded despite the mounter failing")
		}
		for _, want := range []string{testVolume, testMountPoint, "no such device"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("unmount", func(t *testing.T) {
		p, r, m := newTestProviderWithMounter(t)
		provision(t, p, r, defaultSpec())
		r.reset()

		r.scriptMount("/dev/drbd0", testMountPoint)
		m.FailUnmount(errors.New("target is busy"))

		err := p.Unmount(context.Background(), testVolume, testMountPoint)
		if err == nil {
			t.Fatal("Unmount succeeded despite the mounter failing")
		}
		if !strings.Contains(err.Error(), "target is busy") {
			t.Errorf("error %q does not carry the cause", err)
		}
	})
}
