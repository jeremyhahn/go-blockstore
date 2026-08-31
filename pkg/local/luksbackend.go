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
	"context"
	"errors"
)

// luksBackend is the seam between this provider and the LUKS2 implementation
// underneath it.
//
// It exists for the same reason CommandRunner does — the unit tests drive the
// whole provider without root, a block device or device-mapper — but it is a
// separate seam rather than another binary behind CommandRunner, because there
// is no binary any more. Every operation here is performed IN THIS PROCESS by
// github.com/jeremyhahn/go-luks2: the header is parsed in Go, the key is
// derived in Go, and the plaintext mapping is created with device-mapper ioctls
// rather than by forking cryptsetup. Owner ruling 2026-08-29: everything is
// done in pure Go unless there is absolutely no other way.
//
// EVERY key parameter is a []byte borrowed from locked memory for the duration
// of one call and nothing longer. An implementation must not retain it, copy it
// or let it outlive the call — see runWithKey, which owns that window, and
// KeyProvider, which explains what the borrow is protecting.
//
// THERE IS NO RESIZE HERE, and its absence is load-bearing. Growing a dm-crypt
// mapping in place means reloading the device-mapper table underneath the live
// device, which needs the container's master key; go-luks2 exposes neither that
// nor a resize of its own. The only mechanism reachable through it is to remove
// the mapping and unlock again, which is a destructive operation wearing a
// resize's name — the teardown is unconditional and the rebuild can fail, and
// what the caller is left with is not an unresized volume but no plaintext
// device. Rather than offer that behind a reassuring method name, the seam does
// not offer it at all: Resize refuses an attached encrypted volume with
// ErrResizeWhileAttached, and no implementation of this interface has an
// operation capable of tearing down a mapping the caller is using. See
// growDetachedEncryptedFilesystem for the path that does grow one, safely,
// because it opens the mapping itself and owns it for the whole operation.
//
// ctx is honored at call boundaries rather than throughout: go-luks2's API takes
// no context, so an implementation checks for cancellation before it starts and
// runs the operation to completion once it has. That is deliberate. A LUKS
// format or unlock manipulates on-disk metadata and kernel state, and abandoning
// one halfway leaves a container in a state neither the caller nor the next
// operation can reason about; the operations are also bounded by a key
// derivation rather than by a network, so there is no unbounded wait to escape.
type luksBackend interface {
	// Format writes a LUKS2 header onto device with this package's pinned
	// parameters. It destroys whatever was there.
	Format(ctx context.Context, device string, key []byte) error

	// Open unlocks the container on device and exposes its plaintext mapping
	// under the device-mapper name.
	Open(ctx context.Context, device, name string, key []byte) error

	// Close tears the plaintext mapping down.
	Close(ctx context.Context, name string) error

	// TestKey reports whether key opens the container on device WITHOUT
	// unlocking it — no mapping is created and no plaintext device appears.
	TestKey(ctx context.Context, device string, key []byte) error

	// DataOffset reports where a container's data starts, which is what its
	// header costs.
	DataOffset(ctx context.Context, device string) (int64, error)

	// Mapping describes an open plaintext mapping, reporting false when there is
	// no mapping under that name.
	Mapping(ctx context.Context, name string) (mappingInfo, bool, error)

	// Identity returns a device's major:minor, which is the same for every path
	// that leads to it.
	//
	// It rides on this interface rather than standing alone because the one
	// question it answers is a LUKS one — whether the mapping under this
	// provider's deterministic name is over this provider's volume — and because
	// it reads the /dev and /sys trees, which a test that owns neither has to be
	// able to answer for.
	Identity(ctx context.Context, path string) (string, error)
}

// mappingInfo describes an open device-mapper mapping.
type mappingInfo struct {
	// Backing is the most legible path to the device the mapping decrypts,
	// for an error a human has to act on: the dm-canonical
	// /dev/mapper/<vg>-<lv> where the backing device is itself device-mapper,
	// and /dev/<kernel-name> where it is not.
	Backing string

	// BackingID is that device's major:minor, and it — not Backing — is what
	// ownership is decided on. The same device answers to several paths.
	BackingID string
}

// errNoBackingDevice reports a mapping whose backing device could not be
// established.
//
// It fails closed on purpose, and the shape of the failure is the reason: the
// kernel lists what a device-mapper device is stacked on in
// /sys/dev/block/<major>:<minor>/slaves, a dm-crypt target has exactly one
// entry there, and a mapping reporting none or several is not a dm-crypt target
// over one volume. The whole point of looking is to refuse a mapping whose
// identity cannot be established, so an unreadable answer is a refusal rather
// than a pass.
var errNoBackingDevice = errors.New("the mapping reports no single backing device")
