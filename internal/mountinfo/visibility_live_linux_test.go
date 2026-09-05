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

// The visibility property checked against THIS host's live mount table.
//
// # Why it moved out of visibility_test.go
//
// It read /proc/self/mountinfo and excused itself with two runtime skips when
// the read failed or came back empty. conventions/testing-guidelines.md
// §No Skip Guards bars that: the only platform where those excuses were needed
// is one without /proc, and a skip there costs the assertion on every platform
// where it should hold. The prescribed fix is a declared compile-time gate, and
// `_linux_test.go` is one — the file simply does not build where /proc does not
// exist, which is greppable, whereas a skip is not.
//
// On Linux both conditions are now hard failures, and correctly so: a host whose
// /proc/self/mountinfo cannot be read, or holds no records, is not a host this
// package can make any claim about. Reporting that as a pass is the failure this
// gate exists to prevent.
//
// Found by internal/guards' no-runtime-skip scanner (#47).

package mountinfo

import "testing"

// TestVisibilityDoesNotHideAMountWithNoDuplicateOnItsChain states the
// false-positive guard as a property rather than as one host's answer, and runs
// it against whatever this machine has mounted right now.
//
// The rule can only hide a mount when some record shares a mount point with
// another, so a record whose own mount point is unique AND whose every ancestor
// has a unique mount point cannot legitimately be hidden. On a table with no
// stacking at all — the common case — that is every record, and any hidden one
// is a bug.
func TestVisibilityDoesNotHideAMountWithNoDuplicateOnItsChain(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("this host's %s could not be read: %v — on Linux that file always exists, "+
			"so an unreadable one is a broken environment and not a reason to report success", ProcPath, err)
	}
	if len(entries) == 0 {
		t.Fatalf("this host's %s parsed to zero records; a running Linux system always has at least "+
			"the root mount, so an empty table means the parser read nothing", ProcPath)
	}

	shared := make(map[string]int, len(entries))
	for _, e := range entries {
		shared[e.MountPoint]++
	}
	byID := indexByID(entries)
	visible := visibility(entries)

	checked := 0
	for i := range entries {
		unique := true
		for j, steps := i, 0; steps <= len(entries); steps++ {
			if shared[entries[j].MountPoint] > 1 {
				unique = false
				break
			}
			p, ok := parentOf(entries, byID, j)
			if !ok {
				break
			}
			j = p
		}
		if !unique {
			continue
		}
		checked++
		if !visible[i] {
			t.Errorf("mount %d at %q is reported hidden, but no mount point on its chain is named twice",
				entries[i].ID, entries[i].MountPoint)
		}
	}
	if checked == 0 {
		t.Fatal("no record on this host had an unshared chain, so the property was never exercised — the test proved nothing")
	}
	t.Logf("checked %d of %d live records with no duplicated mount point on their chain", checked, len(entries))
}
