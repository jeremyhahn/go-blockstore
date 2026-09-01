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

package mountinfo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadReadsTheLiveTable exercises the parser against whatever this host has
// mounted, which is the only input that is not one this test wrote. A format
// the kernel emits and the parser rejects shows up here and nowhere else.
func TestLoadReadsTheLiveTable(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the live mount table is empty, which cannot be")
	}

	if _, ok := EntryAt(entries, "/"); !ok {
		t.Error("the live mount table has no root filesystem")
	}
	for _, e := range entries {
		if e.MountPoint == "" {
			t.Errorf("entry %+v has no mount point", e)
		}
		if !strings.HasPrefix(e.MountPoint, "/") {
			t.Errorf("mount point %q is not absolute", e.MountPoint)
		}
	}
}

func TestDeviceNumberRefusesNonBlockDevices(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for name, path := range map[string]string{
		"a regular file":     regular,
		"a directory":        dir,
		"a character device": "/dev/null",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := DeviceNumber(path)
			if !errors.Is(err, ErrNotBlockDevice) {
				t.Fatalf("DeviceNumber(%s) = %v, want ErrNotBlockDevice", path, err)
			}
			var devErr *DeviceError
			if !errors.As(err, &devErr) || devErr.Path != path {
				t.Errorf("error does not carry the path: %v", err)
			}
		})
	}
}

func TestDeviceNumberReportsAMissingPath(t *testing.T) {
	_, _, err := DeviceNumber(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("DeviceNumber succeeded for a path that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("DeviceNumber = %v, want it to wrap os.ErrNotExist", err)
	}
}
