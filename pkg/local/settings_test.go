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

package local

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestNewFromSettings(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(keyFile, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p, err := NewFromSettings(map[string]string{
		SettingVolumeGroup:        "vg0",
		SettingNodeID:             "node-a",
		SettingEncrypted:          "true",
		SettingLUKSKeyFile:        keyFile,
		SettingSnapshotCoWPercent: "35",
		SettingWipeOnDelete:       "true",
	})
	if err != nil {
		t.Fatalf("NewFromSettings: %v", err)
	}
	if p.volumeGroup != "vg0" {
		t.Errorf("volumeGroup = %q, want vg0", p.volumeGroup)
	}
	if p.NodeID() != "node-a" {
		t.Errorf("NodeID = %q, want node-a", p.NodeID())
	}
	if !p.encrypted {
		t.Error("encrypted = false, want true")
	}
	if p.snapshotCoWPercent != 35 {
		t.Errorf("snapshotCoWPercent = %d, want 35", p.snapshotCoWPercent)
	}
	if p.keyProvider == nil {
		t.Error("keyProvider is nil, want the file-backed provider")
	}
	if !p.wipeOnDelete {
		t.Error("wipeOnDelete = false, want true")
	}
}

func TestNewFromSettingsDefaults(t *testing.T) {
	p, err := NewFromSettings(map[string]string{SettingVolumeGroup: "vg0"})
	if err != nil {
		t.Fatalf("NewFromSettings: %v", err)
	}
	if p.snapshotCoWPercent != defaultSnapshotCoWPercent {
		t.Errorf("snapshotCoWPercent = %d, want the default %d", p.snapshotCoWPercent, defaultSnapshotCoWPercent)
	}
	if p.encrypted {
		t.Error("encrypted = true, want false by default")
	}
	if p.wipeOnDelete {
		t.Error("wipeOnDelete = true, want false by default")
	}
	if p.NodeID() == "" {
		t.Error("NodeID is empty, want the hostname")
	}
}

// TestNewFromSettingsRejectsUnknownKeys is the check that keeps a misspelled
// "encrypted" from silently provisioning plaintext volumes.
func TestNewFromSettingsRejectsUnknownKeys(t *testing.T) {
	_, err := NewFromSettings(map[string]string{
		SettingVolumeGroup: "vg0",
		"encrpyted":        "true", //nolint:misspell // the typo IS the fixture: a misspelled key must be rejected, not ignored.
		"volumegroup":      "vg1",
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("NewFromSettings = %v, want common.ErrInvalidArgument", err)
	}
	// Both typos are named, in a stable order, so the operator fixes them in
	// one pass.
	//nolint:misspell // asserts the error repeats the operator's typo verbatim, so they can find it.
	if !strings.Contains(err.Error(), "encrpyted, volumegroup") {
		t.Errorf("error = %q, want both unknown keys listed alphabetically", err)
	}
}

func TestNewFromSettingsRejectsBadValues(t *testing.T) {
	cases := map[string]map[string]string{
		"missing volume group": {},
		"hostile volume group": {SettingVolumeGroup: "vg0; id"},
		"non-boolean encrypted": {
			SettingVolumeGroup: "vg0",
			SettingEncrypted:   "yes please",
		},
		"encrypted without a key file": {
			SettingVolumeGroup: "vg0",
			SettingEncrypted:   "true",
		},
		"non-boolean wipe": {
			SettingVolumeGroup:  "vg0",
			SettingWipeOnDelete: "sometimes",
		},
		"non-integer percent": {
			SettingVolumeGroup:        "vg0",
			SettingSnapshotCoWPercent: "a lot",
		},
		"out-of-range percent": {
			SettingVolumeGroup:        "vg0",
			SettingSnapshotCoWPercent: "0",
		},
	}

	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewFromSettings(settings); !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("NewFromSettings = %v, want common.ErrInvalidArgument", err)
			}
		})
	}
}

// TestNewFromSettingsAcceptsBooleanSpellings covers the forms an operator is
// likely to write in a config file.
func TestNewFromSettingsAcceptsBooleanSpellings(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(keyFile, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, spelling := range []string{"true", "TRUE", "1", "t"} {
		p, err := NewFromSettings(map[string]string{
			SettingVolumeGroup: "vg0",
			SettingEncrypted:   spelling,
			SettingLUKSKeyFile: keyFile,
		})
		if err != nil {
			t.Fatalf("NewFromSettings(encrypted=%q): %v", spelling, err)
		}
		if !p.encrypted {
			t.Errorf("encrypted=%q did not enable encryption", spelling)
		}
	}

	for _, spelling := range []string{"false", "0", "f", ""} {
		p, err := NewFromSettings(map[string]string{
			SettingVolumeGroup: "vg0",
			SettingEncrypted:   spelling,
		})
		if err != nil {
			t.Fatalf("NewFromSettings(encrypted=%q): %v", spelling, err)
		}
		if p.encrypted {
			t.Errorf("encrypted=%q enabled encryption", spelling)
		}
	}
}
