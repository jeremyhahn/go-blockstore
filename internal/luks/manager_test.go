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

package luks

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// scriptedBackend answers Mapping, Identity and DataOffset from fixed values,
// so every shape MeasureMapping has to refuse can be produced on demand — none
// of them can be made on a real host without a kernel that misbehaves.
type scriptedBackend struct {
	Backend // nil: every method not scripted here panics, which is the point

	info      MappingInfo
	exists    bool
	mapErr    error
	identity  string
	offset    int64
	offsetErr error
}

func (s scriptedBackend) Mapping(context.Context, string) (MappingInfo, bool, error) {
	return s.info, s.exists, s.mapErr
}

func (s scriptedBackend) Identity(context.Context, string) (string, error) { return s.identity, nil }

func (s scriptedBackend) DataOffset(context.Context, string) (int64, error) {
	return s.offset, s.offsetErr
}

// TestMeasureMappingDecidesFreshnessAndRefusesWhatItCannotSize is the
// stale-mapping measurement, branch by branch.
//
// The two answers that matter are a mapping that still covers its device and
// one that has fallen behind it; the fixture's sizes are the ones a 1 GiB
// volume with a 16 MiB header produces. Every other shape is a refusal rather
// than either answer, because the whole point of measuring is to refuse what
// cannot be established: an unreadable offset, a mapping of no length, a device
// no larger than its header, and — the shape nothing above should ever act on —
// a mapping LONGER than the device's data area, which is a device that shrank
// under a live mapping.
func TestMeasureMappingDecidesFreshnessAndRefusesWhatItCannotSize(t *testing.T) {
	const (
		header = int64(HeaderBytes)
		usable = int64(1) << 30
		device = usable + header
	)
	fresh := MappingInfo{BackingID: "fd:7", SizeBytes: usable, BackingSizeBytes: device}

	m := func(b scriptedBackend) *Manager {
		return NewManager(b, nil, ReplicatedMappingPrefix+"vg0.", "test")
	}
	ok := func(info MappingInfo) scriptedBackend {
		return scriptedBackend{info: info, exists: true, identity: "fd:7", offset: header}
	}

	t.Run("a mapping that covers its device is fresh", func(t *testing.T) {
		size, err := m(ok(fresh)).MeasureMapping(context.Background(), "vol1", "/dev/drbd0")
		if err != nil {
			t.Fatalf("MeasureMapping: %v", err)
		}
		if size.Stale() {
			t.Errorf("Stale() = true for %+v", size)
		}
		if size.MappingBytes != usable || size.DataBytes != usable {
			t.Errorf("MeasureMapping = %+v, want mapping and data both %d", size, usable)
		}
	})

	t.Run("a device that grew under the mapping makes it stale", func(t *testing.T) {
		grown := fresh
		grown.BackingSizeBytes = device + (512 << 20)
		size, err := m(ok(grown)).MeasureMapping(context.Background(), "vol1", "/dev/drbd0")
		if err != nil {
			t.Fatalf("MeasureMapping: %v", err)
		}
		if !size.Stale() {
			t.Errorf("Stale() = false for %+v: the device is larger than the mapping by half a GiB", size)
		}
		if size.DataBytes != usable+(512<<20) {
			t.Errorf("DataBytes = %d, want %d", size.DataBytes, usable+(512<<20))
		}
	})

	refusals := map[string]struct {
		backend scriptedBackend
		want    string
	}{
		"no mapping is open": {
			backend: scriptedBackend{exists: false, identity: "fd:7", offset: header},
			want:    "no open mapping",
		},
		"the mapping is over another device": {
			backend: scriptedBackend{info: fresh, exists: true, identity: "fd:8", offset: header},
			want:    "not over this volume",
		},
		"the mapping cannot be looked up": {
			backend: scriptedBackend{mapErr: errors.New("dm ioctl failed"), identity: "fd:7", offset: header},
			want:    "dm ioctl failed",
		},
		"the header's data offset cannot be read": {
			backend: scriptedBackend{info: fresh, exists: true, identity: "fd:7", offsetErr: errors.New("header unreadable")},
			want:    "header unreadable",
		},
		"the mapping reports no length": {
			backend: ok(MappingInfo{BackingID: "fd:7", SizeBytes: 0, BackingSizeBytes: device}),
			want:    "cannot be right",
		},
		"the device is no larger than its header": {
			backend: ok(MappingInfo{BackingID: "fd:7", SizeBytes: usable, BackingSizeBytes: header}),
			want:    "no larger than its own",
		},
		"the device shrank under the mapping": {
			backend: ok(MappingInfo{BackingID: "fd:7", SizeBytes: usable, BackingSizeBytes: device - 4096}),
			want:    "shrank under a live mapping",
		},
	}
	for name, tc := range refusals {
		t.Run(name, func(t *testing.T) {
			size, err := m(tc.backend).MeasureMapping(context.Background(), "vol1", "/dev/drbd0")
			if err == nil {
				t.Fatalf("MeasureMapping = %+v, want a refusal", size)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("MeasureMapping = %v, want it to say %q", err, tc.want)
			}
			if size != (MappingSize{}) {
				t.Errorf("a refusal returned a measurement: %+v", size)
			}
		})
	}
}
