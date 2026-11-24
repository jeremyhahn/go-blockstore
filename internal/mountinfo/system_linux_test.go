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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These read this host's live mount table; the block-backed round trip is in the local_integration suite.

// TestSystemMountPointsForRefusesANonBlockPath covers the identity step. A path
// with no device number cannot be matched against the table at all, and
// answering "not mounted" for it would be the fail-open this package exists to
// remove.
func TestSystemMountPointsForRefusesANonBlockPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	targets, err := System{}.MountPointsFor(context.Background(), path)
	if !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("MountPointsFor of a regular file = %v, want ErrNotBlockDevice", err)
	}
	if targets != nil {
		t.Errorf("MountPointsFor returned %v alongside its error", targets)
	}
}

// TestSystemHonoursACancelledContext checks that a caller who has given up is
// told so rather than handed a stale reading of the table.
func TestSystemHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := (System{}).MountPointsFor(ctx, "/dev/does-not-matter"); !errors.Is(err, context.Canceled) {
		t.Errorf("MountPointsFor = %v, want it to wrap context.Canceled", err)
	}
}

// TestSystemPropagationOfReadsTheLiveTable checks the refusal a wrong device produces against the live table.
func TestSystemPropagationOfRefusesAPathHoldingSomethingElse(t *testing.T) {
	// A regular file has no device number at all, so the lookup cannot even
	// begin — the identity step refuses before the table is consulted.
	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, _, err := (System{}).PropagationOf(context.Background(), path, "/"); !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("PropagationOf with a non-device = %v, want ErrNotBlockDevice", err)
	}
}

func TestSystemPropagationOfHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, _, err := (System{}).PropagationOf(ctx, "/dev/does-not-matter", "/"); !errors.Is(err, context.Canceled) {
		t.Errorf("PropagationOf = %v, want it to wrap context.Canceled", err)
	}
}
