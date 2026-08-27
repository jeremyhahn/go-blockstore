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

import "context"

// VolumeProvider is the common interface implemented by all block-storage
// backends. It manages the lifecycle of block volumes: provisioning, attaching
// them to nodes as block devices, mounting, resizing, snapshotting and
// deletion. All methods are context-aware so callers can bound and cancel
// potentially long-running operations.
//
// Providers own validation of the free-form strings they are handed —
// VolumeSpec.Name, VolumeSpec.FSType and MountOptions.Flags among them. These
// interfaces put no constraints on those values, so a provider must treat every
// one as hostile and validate it against an allowlist before it reaches mount,
// lvcreate, drbdadm or any other system tool. Values must be passed as separate
// argv elements to an exec'd binary, never interpolated into a shell command
// line, and a value that fails validation is rejected with an error rather than
// escaped and passed on.
type VolumeProvider interface {
	// Provision creates a new volume matching the given spec and returns the
	// resulting Volume. It returns ErrAlreadyExists if a volume with the same
	// identity already exists.
	//
	// A non-empty spec.SourceSnapshotID provisions the volume from that
	// snapshot rather than empty, giving the new volume the snapshot's
	// contents; it returns ErrSnapshotNotFound if no such snapshot exists. The
	// rest of the spec still applies — notably spec.SizeBytes, which must be at
	// least the snapshot's size, since a provider is not required to support
	// shrinking during restore and returns ErrUnsupported if asked to.
	Provision(ctx context.Context, spec VolumeSpec) (Volume, error)

	// Attach makes the volume available as a block device on the given node and
	// returns the resulting AttachInfo. It returns ErrNotFound if the volume
	// does not exist.
	Attach(ctx context.Context, volID string, node NodeID) (AttachInfo, error)

	// Detach removes the volume's block device from the given node. It returns
	// ErrNotFound if the volume does not exist.
	Detach(ctx context.Context, volID string, node NodeID) error

	// Mount mounts an attached volume at the given target path using the
	// supplied options. It returns ErrNotFound if the volume does not exist and
	// ErrNotAttached if the volume is not attached on this node — mounting
	// requires a block device, so Attach must have succeeded here first.
	Mount(ctx context.Context, volID, target string, opts MountOptions) error

	// Unmount unmounts the volume from the given target path. It returns
	// ErrNotFound if the volume does not exist. Unmounting a target the volume
	// is not mounted at is not an error, so a teardown path converges whether
	// or not the mount ever happened.
	Unmount(ctx context.Context, volID, target string) error

	// Resize grows the volume to newSize bytes. It returns ErrNotFound if the
	// volume does not exist. Providers are not required to support shrinking; a
	// newSize below the current capacity returns ErrUnsupported on a provider
	// that cannot shrink.
	Resize(ctx context.Context, volID string, newSize int64) error

	// Snapshot creates a named point-in-time snapshot of the volume and returns
	// its SnapshotID. It returns ErrNotFound if the volume does not exist,
	// ErrAlreadyExists if the volume already has a snapshot by that name, and
	// ErrUnsupported on a provider without snapshot support.
	Snapshot(ctx context.Context, volID, name string) (SnapshotID, error)

	// ListSnapshots returns the snapshots taken from the volume, in unspecified
	// order. A volume with no snapshots yields an empty slice and a nil error;
	// absence of snapshots is not ErrSnapshotNotFound. It returns ErrNotFound
	// if the volume does not exist and ErrUnsupported on a provider without
	// snapshot support.
	ListSnapshots(ctx context.Context, volID string) ([]SnapshotInfo, error)

	// DeleteSnapshot permanently removes the snapshot. It returns
	// ErrSnapshotNotFound if the snapshot does not exist and ErrUnsupported on
	// a provider without snapshot support. Whether volumes provisioned from the
	// snapshot survive its deletion is provider-specific: a backend that keeps
	// restored volumes dependent on the snapshot may refuse the delete rather
	// than break them.
	DeleteSnapshot(ctx context.Context, snapID SnapshotID) error

	// Delete permanently removes the volume. It returns ErrNotFound if the
	// volume does not exist.
	Delete(ctx context.Context, volID string) error

	// Status reports the current state of the volume. It returns ErrNotFound if
	// the volume does not exist.
	Status(ctx context.Context, volID string) (VolumeStatus, error)
}

// ReplicatedProvider extends VolumeProvider with the operations required to
// manage replicated (primary/secondary) volumes, such as those backed by DRBD.
type ReplicatedProvider interface {
	VolumeProvider

	// Promote makes the local copy of the volume the primary, allowing
	// read/write access.
	Promote(ctx context.Context, volID string) error

	// Demote makes the local copy of the volume a secondary, allowing only
	// replication.
	Demote(ctx context.Context, volID string) error

	// ReplicationState reports the current replication state of the volume. It
	// returns ErrNotReplicated if the volume is not replicated.
	ReplicationState(ctx context.Context, volID string) (ReplState, error)
}
