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

// The Table implementation reads the running kernel, so these drive it against
// this host's real mount table rather than a fixture. That is the point: the
// parser tests prove the format is understood, and these prove the seam is
// wired to it — a System that opened the wrong file passes every fixture test
// and finds nothing here.
//
// What is NOT here is the block-backed round trip, which needs a device node
// this process can stat. A container has a mount table and no /dev to speak of
// — measured: the CI image's /dev holds null, zero, random and the standard
// descriptors, and the overlay's backing device is not among them — so a test
// requiring one fails on the runner while passing on a workstation. That round
// trip lives in the local_integration suite, which builds a real logical volume
// to check it against.

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

// TestSystemPropagationOfReadsTheLiveTable drives the propagation lookup
// against this host's real table. The root filesystem is always mounted, so the
// lookup has something to find on any Linux, container included — but it is
// asked about by DEVICE, and a container has no device node to name, so the
// device-backed half of this belongs to the integration suite. What is checked
// here is the refusal a wrong device produces.
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
