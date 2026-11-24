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

package common

import "errors"

var (
	// ErrNotFound is returned when a requested volume does not exist.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is returned when provisioning a volume, or snapshotting
	// under a name, that already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrSnapshotNotFound is returned when an operation names a snapshot that does not exist.
	ErrSnapshotNotFound = errors.New("snapshot not found")

	// ErrNotAttached is returned when an operation needs the volume attached on the local node and it is not.
	ErrNotAttached = errors.New("not attached")

	// ErrUnsupported is returned when a provider does not implement an optional operation.
	ErrUnsupported = errors.New("operation not supported by provider")

	// ErrInvalidArgument reports input a provider's validation rejected; providers wrap it with the offending value, e.g. fmt.Errorf("%w: volume name %q", ErrInvalidArgument, name).
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrNotReplicated is returned when a replication operation is requested for
	// a volume that is not replicated.
	ErrNotReplicated = errors.New("not replicated")

	// ErrNotPrimary is returned when an operation needs the local node to be primary for a replicated volume; promote, then retry.
	ErrNotPrimary = errors.New("not primary on this node")

	// ErrHasSnapshots is returned by Delete while snapshots of the volume exist; deletion does not cascade.
	ErrHasSnapshots = errors.New("volume has snapshots")

	// ErrProviderNotRegistered is returned when a provider is requested by a
	// name that has not been registered.
	ErrProviderNotRegistered = errors.New("provider not registered")

	// ErrLeaseHeld is returned by Coordinator.AcquireLease when another live lease holds the key; implementations wrap the backend error with it.
	ErrLeaseHeld = errors.New("lease already held")
)
