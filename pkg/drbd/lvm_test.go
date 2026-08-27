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
	"strings"
	"testing"
)

// TestParseLVMInt covers the shapes an lvs report field arrives in. LVM formats
// report sizes to two decimal places by default, so "--units b --nosuffix" does
// not reliably yield a bare integer, and a parser that only accepted one would
// silently read every size as zero — which reads downstream as "this snapshot
// has no origin size" and refuses valid restores.
func TestParseLVMInt(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"1073741824", 1073741824},
		{"1073741824.00", 1073741824},
		{"1073741824.99", 1073741824}, // A byte count has no fraction to round.
		{"  1073741824  ", 1073741824},
		{"1073741824B", 1073741824},
		{"1073741824b", 1073741824},
		{"1073741824.00B", 1073741824},
		{"0", 0},
		{"9007199254740993", 9007199254740993}, // Beyond float64's exact range.

		{"", 0},
		{"   ", 0},
		{"not a number", 0},
		{"1,073,741,824", 0},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := parseLVMInt(tc.in); got != tc.want {
				t.Errorf("parseLVMInt(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestLVEntrySizes drives the same parsing through the fields that use it.
func TestLVEntrySizes(t *testing.T) {
	e := lvEntry{Size: "214748364.00", OriginSize: "1073741824.00"}
	if got := e.sizeBytes(); got != 214748364 {
		t.Errorf("sizeBytes = %d, want 214748364", got)
	}
	if got := e.originSizeBytes(); got != 1073741824 {
		t.Errorf("originSizeBytes = %d, want 1073741824", got)
	}
}

func TestLVEntryCreatedAt(t *testing.T) {
	tests := []struct {
		in   string
		zero bool
	}{
		{"2026-08-26 03:00:00 -0500", false},
		{"2026-08-26 03:00:00 UTC", false},
		{"2026-08-26T03:00:00Z", false},
		{"  2026-08-26 03:00:00 -0500  ", false},
		// A timestamp is reporting detail, so an unparseable one yields the zero
		// time rather than failing a whole snapshot listing.
		{"yesterday", true},
		{"", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			e := lvEntry{Time: tc.in}
			got := e.createdAt()
			if got.IsZero() != tc.zero {
				t.Errorf("createdAt(%q) = %v, want zero=%v", tc.in, got, tc.zero)
			}
			if !tc.zero && got.Year() != 2026 {
				t.Errorf("createdAt(%q) = %v, want a 2026 timestamp", tc.in, got)
			}
		})
	}
}

func TestSnapshotIDRoundTrip(t *testing.T) {
	p, _ := newTestProvider(t)

	id := p.snapshotID("vol1", "nightly")
	if id != "vg0/vol1.snap.nightly" {
		t.Fatalf("snapshotID = %q", id)
	}
	vol, snap, err := p.parseSnapshotID(id)
	if err != nil {
		t.Fatalf("parseSnapshotID(%q): %v", id, err)
	}
	if vol != "vol1" || snap != "nightly" {
		t.Errorf("parseSnapshotID = (%q, %q), want (vol1, nightly)", vol, snap)
	}
}

func TestRoundUpTo(t *testing.T) {
	const extent = int64(4) << 20
	tests := []struct {
		n, unit, want int64
	}{
		{0, extent, 0},
		{1, extent, extent},
		{extent, extent, extent},
		{extent + 1, extent, 2 * extent},
		{1073741824, extent, 1073741824}, // Already a whole number of extents.
		{1073815552, extent, 1077936128},
		// An unknown granularity leaves the value alone rather than guessing.
		{12345, 0, 12345},
		{12345, -1, 12345},
	}
	for _, tc := range tests {
		if got := roundUpTo(tc.n, tc.unit); got != tc.want {
			t.Errorf("roundUpTo(%d, %d) = %d, want %d", tc.n, tc.unit, got, tc.want)
		}
	}
}

func TestLVEntryExtentSize(t *testing.T) {
	// The accessors take a pointer receiver — the report row is wide enough
	// that copying it per call showed up in the linter — so the value needs
	// somewhere addressable to live.
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"4194304", 4 << 20},
		{"4194304.00", 4 << 20},
		{"", 0},
	} {
		e := lvEntry{ExtentSize: tc.in}
		if got := e.extentSizeBytes(); got != tc.want {
			t.Errorf("extentSizeBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestLVEntryUsedBytes covers the difference between the space a snapshot was
// GIVEN and the space it OCCUPIES, which is what SnapshotInfo.SizeBytes means,
// and the line between an absent measurement and an unreadable one.
//
// Absent is a real answer: LVM populates data_percent only while the kernel has
// the device mapped, so an inactive snapshot reporting nothing is its ordinary
// state — measured on 2.03.16 — and this provider leaves snapshots inactive.
// Unreadable is not an answer at all, and coercing it to 0 would hand a caller
// a fabricated occupancy to size a restore against.
const (
	attrActiveSnapshot   = "swi-a-s---"
	attrInactiveSnapshot = "swi---s---"
	attrActiveVolume     = "-wi-a-----"
)

func TestLVEntryUsedBytes(t *testing.T) {
	tests := []struct {
		name    string
		size    string
		percent string
		origin  string
		attr    string
		want    int64
		wantErr bool
	}{
		{name: "a quarter used", size: "1000000", percent: "25.00", origin: "vol1", attr: attrActiveSnapshot, want: 250000},
		{name: "nothing written yet", size: "1000000", percent: "0.00", origin: "vol1", attr: attrActiveSnapshot},
		{name: "full", size: "1000000", percent: "100.00", origin: "vol1", attr: attrActiveSnapshot, want: 1000000},

		// The declined half of the review: empty on an INACTIVE snapshot is
		// the normal state, and erroring would break every listing of a volume
		// group holding one — and diverge from pkg/local, which reports 0 here
		// for the same measured reason.
		{name: "inactive snapshot has no figure to report", size: "1000000", percent: "", origin: "vol1", attr: attrInactiveSnapshot},
		{name: "a plain volume never reports one", size: "1000000", percent: "", attr: attrActiveVolume},

		// Empty on an ACTIVE snapshot is different: the kernel has a figure and
		// lvs failed to render it.
		{name: "active snapshot with no figure", size: "1000000", percent: "", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},

		// Unreadable in any form, active or not. These used to read as 0.
		{name: "unparseable", size: "1000000", percent: "lots", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},
		{name: "negative", size: "1000000", percent: "-1", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},
		{name: "above 100", size: "1000000", percent: "120.00", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},
		{name: "not a number, but finite-looking", size: "1000000", percent: "NaN", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},
		{name: "infinite", size: "1000000", percent: "+Inf", origin: "vol1", attr: attrActiveSnapshot, wantErr: true},
		// Unreadable even on an inactive snapshot: absent is an answer,
		// garbage is not.
		{name: "unparseable while inactive", size: "1000000", percent: "lots", origin: "vol1", attr: attrInactiveSnapshot, wantErr: true},

		{name: "no size", size: "", percent: "50.00", origin: "vol1", attr: attrActiveSnapshot},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := lvEntry{Name: "vol1.snap.nightly", VG: testVG, Size: tc.size, DataPercent: tc.percent, Origin: tc.origin, Attr: tc.attr}
			got, err := e.usedBytes()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("usedBytes(data_percent=%q) = %d with no error, want an error", tc.percent, got)
				}
				// The refusal has to say which volume and what it read, or it
				// cannot be chased down in a volume group of many.
				for _, want := range []string{"vol1.snap.nightly", testVG} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the error does not name %q: %v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("usedBytes(size=%q, data_percent=%q) = %v, want %d", tc.size, tc.percent, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("usedBytes(size=%q, data_percent=%q) = %d, want %d", tc.size, tc.percent, got, tc.want)
			}
		})
	}
}
