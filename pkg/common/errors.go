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

	// ErrSnapshotNotFound is returned when an operation names a snapshot that
	// does not exist — deleting one, or provisioning from a VolumeSpec whose
	// SourceSnapshotID names no snapshot. It is distinct from ErrNotFound so a
	// caller can tell a missing snapshot from a missing volume.
	ErrSnapshotNotFound = errors.New("snapshot not found")

	// ErrNotAttached is returned when an operation requires the volume to be
	// attached on the local node and it is not, such as mounting a volume that
	// was never attached. It marks a sequencing mistake rather than a failure
	// of the operation itself: the caller attaches first and retries.
	ErrNotAttached = errors.New("not attached")

	// ErrUnsupported is returned when a provider does not implement an
	// optional operation — shrinking on Resize, or snapshots on a backend that
	// has none. The request is well-formed; this backend simply cannot serve
	// it, so retrying or reconfiguring is pointless without choosing another
	// provider.
	ErrUnsupported = errors.New("operation not supported by provider")

	// ErrInvalidArgument is the portable sentinel for hostile or malformed input
	// rejected by a provider's own validation — a volume or snapshot name
	// outside the character set a backend will accept, a filesystem type it will
	// not create, a mount flag not on its allowlist, a mount target that is not
	// a clean absolute path, a node that appears nowhere in the backend's
	// configuration.
	//
	// It is the counterpart to ErrUnsupported rather than a variant of it.
	// ErrUnsupported answers a well-formed request this backend cannot serve;
	// this one says the request never became well-formed, so no other provider
	// would take it either and the fix belongs to whoever supplied the value.
	// The VolumeProvider doc makes validation the provider's job; this is what
	// providers report it with, so a caller writes one branch instead of one per
	// backend.
	//
	// Providers WRAP it with the detail that identifies the offending value:
	//
	//	return fmt.Errorf("%w: volume name %q contains %q", common.ErrInvalidArgument, name, string(c))
	//
	// Returning the bare sentinel passes the caller a rejection with nothing to
	// act on — which value, and why — and validation errors are read by whoever
	// has to correct the input.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrNotReplicated is returned when a replication operation is requested for
	// a volume that is not replicated.
	ErrNotReplicated = errors.New("not replicated")

	// ErrProviderNotRegistered is returned when a provider is requested by a
	// name that has not been registered.
	ErrProviderNotRegistered = errors.New("provider not registered")

	// ErrLeaseHeld is returned by Coordinator.AcquireLease when the key is
	// already held by another live lease. It is the expected, non-fatal outcome
	// of losing a contended acquisition (e.g. another node is the current
	// leader) and is distinct from an operational failure, so callers can back
	// off rather than treat it as an error. A Coordinator implementation maps
	// its backend-specific "lease held" condition to this sentinel so callers
	// remain backend-agnostic.
	//
	// Implementations WRAP the backend error rather than returning the bare
	// sentinel, so that both survive:
	//
	//	return fmt.Errorf("%w: %w", common.ErrLeaseHeld, heldErr)
	//
	// errors.Is(err, ErrLeaseHeld) then matches for the portable branch, while
	// errors.As still recovers the backend error and the detail it carries —
	// the contended key, in the case of go-qrdb's *sdk.LeaseHeldError. Return
	// the bare sentinel and that key is lost to logs and diagnostics.
	ErrLeaseHeld = errors.New("lease already held")
)
