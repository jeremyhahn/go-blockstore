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

	"github.com/jeremyhahn/go-enclave"
)

// Backend is the seam between the providers and go-luks2, which does every operation in process.
// Each key is an enclave lent for one call; an implementation must not destroy or retain it.
// There is deliberately no resize: MappingInfo reports the mapping and backing sizes so a provider can refuse a stale mapping.
type Backend interface {
	// Format writes a LUKS2 header onto device with this package's pinned
	// parameters. It destroys whatever was there.
	Format(ctx context.Context, device string, key *enclave.MemoryEnclave) error

	// Open unlocks the container on device and exposes its plaintext mapping
	// under the device-mapper name.
	Open(ctx context.Context, device, name string, key *enclave.MemoryEnclave) error

	// Close tears the plaintext mapping down.
	Close(ctx context.Context, name string) error

	// TestKey reports whether key opens the container on device without unlocking it.
	TestKey(ctx context.Context, device string, key *enclave.MemoryEnclave) error

	// DataOffset reports where a container's data starts, which is what its
	// header costs.
	DataOffset(ctx context.Context, device string) (int64, error)

	// Mapping describes an open plaintext mapping, reporting false when there is
	// no mapping under that name.
	Mapping(ctx context.Context, name string) (MappingInfo, bool, error)

	// Identity returns a device's major:minor, the same for every path to it.
	Identity(ctx context.Context, path string) (string, error)
}

// MappingInfo describes an open device-mapper mapping.
type MappingInfo struct {
	// Backing is the most legible path to the backing device: /dev/mapper/<vg>-<lv> for device-mapper, else /dev/<kernel-name>.
	Backing string

	// BackingID is that device's major:minor, and it — not Backing — is what
	// ownership is decided on. The same device answers to several paths.
	BackingID string

	// SizeBytes is the mapping's length, fixed when the mapping was loaded.
	SizeBytes int64

	// BackingSizeBytes is the backing device's current size, read in the same sysfs walk as SizeBytes.
	BackingSizeBytes int64
}

// ErrNoBackingDevice reports a mapping without exactly one backing device; it fails closed.
var ErrNoBackingDevice = errors.New("the mapping reports no single backing device")
