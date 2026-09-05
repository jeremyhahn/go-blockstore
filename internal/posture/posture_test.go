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

package posture

import (
	"strings"
	"testing"
)

// TestStringSaysTheThirdState is the whole reason this type exists: an
// unchecked guard is a LINE, not an omission. An operator reading a list of
// three guards cannot tell it from a list of four.
func TestStringSaysTheThirdState(t *testing.T) {
	rendered := Posture{
		Component: "drbd",
		Guards: []GuardStatus{
			{Name: "mount(2) privilege", Active: true, Detail: "verified at startup"},
			{Name: "mount propagation", Active: false, Detail: "set mount_propagation=shared"},
			{Name: "no detail at all", Active: true},
		},
	}.String()

	for _, want := range []string{
		"go-blockstore/drbd guards:",
		"mount(2) privilege: checked — verified at startup",
		"mount propagation: NOT CHECKED — set mount_propagation=shared",
		"no detail at all: checked",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("posture reads:\n%s\nwant a line %q", rendered, want)
		}
	}

	// NOT CHECKED is upper case and checked is not, so the eye finds the gaps in
	// a list of a dozen lines. A rendering that shouted both would lose that.
	if strings.Contains(rendered, "NOT CHECKED — verified") {
		t.Error("a checked guard rendered as NOT CHECKED")
	}
	if lines := strings.Count(rendered, "\n"); lines != 3 {
		t.Errorf("posture has %d guard lines, want 3:\n%s", lines, rendered)
	}
}

// TestStringWithoutAComponent keeps the rendering usable for a caller that did
// not name one, rather than printing a stray separator.
func TestStringWithoutAComponent(t *testing.T) {
	rendered := Posture{Guards: []GuardStatus{{Name: "a guard"}}}.String()
	if !strings.HasPrefix(rendered, "go-blockstore guards:") {
		t.Errorf("posture reads:\n%s\nwant it to open with an unqualified header", rendered)
	}
}

// TestUnchecked returns the part worth acting on, and only that part.
func TestUnchecked(t *testing.T) {
	off := Posture{Guards: []GuardStatus{
		{Name: "on", Active: true},
		{Name: "off", Active: false},
		{Name: "also off", Active: false},
	}}.Unchecked()

	if len(off) != 2 || off[0].Name != "off" || off[1].Name != "also off" {
		t.Fatalf("Unchecked() = %v, want the two inactive guards in order", off)
	}
	if none := (Posture{Guards: []GuardStatus{{Name: "on", Active: true}}}).Unchecked(); none != nil {
		t.Errorf("Unchecked() = %v over an all-checked posture, want nil", none)
	}
}
