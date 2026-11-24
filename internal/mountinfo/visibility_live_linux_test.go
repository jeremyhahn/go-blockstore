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

// Checks the visibility property against this host's live mount table; an unreadable or empty table fails.

package mountinfo

import "testing"

// TestVisibilityDoesNotHideAMountWithNoDuplicateOnItsChain: a record with a unique mount point and unique ancestors is never hidden.
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
