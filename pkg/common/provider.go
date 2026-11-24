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

// VolumeProvider is the interface every block-storage backend implements: provision, attach, mount, resize, snapshot, delete.
// Providers validate every free-form string against an allowlist, pass values as separate argv elements, and reject bad values with ErrInvalidArgument.
type VolumeProvider interface {
	// Provision creates a volume of spec.SizeBytes usable capacity, from spec.SourceSnapshotID when set; ErrAlreadyExists, ErrSnapshotNotFound, or ErrUnsupported for a shrinking restore.
	Provision(ctx context.Context, spec VolumeSpec) (Volume, error)

	// Attach exposes the volume as a block device on node; ErrNotFound, ErrUnsupported for a node this provider cannot serve, ErrInvalidArgument for an unknown node.
	Attach(ctx context.Context, volID string, node NodeID) (AttachInfo, error)

	// Detach removes the volume's block device from the given node. It returns
	// ErrNotFound if the volume does not exist.
	Detach(ctx context.Context, volID string, node NodeID) error

	// Mount mounts an attached volume at target; ErrNotFound, or ErrNotAttached when not attached on this node.
	Mount(ctx context.Context, volID, target string, opts MountOptions) error

	// Unmount unmounts the volume from target; ErrNotFound. An unmounted target is not an error.
	Unmount(ctx context.Context, volID, target string) error

	// Resize grows the volume to newSize usable bytes, and its filesystem where it can be grown in the current state; a repeat finishes an incomplete grow.
	// ErrNotFound; ErrUnsupported for a shrink. The result may be rounded up, never down.
	Resize(ctx context.Context, volID string, newSize int64) error

	// Snapshot creates a named point-in-time snapshot; ErrNotFound, ErrAlreadyExists, ErrUnsupported, or ErrNotPrimary on a replicated secondary.
	Snapshot(ctx context.Context, volID, name string) (SnapshotID, error)

	// ListSnapshots returns the volume's snapshots in unspecified order; none is an empty slice. ErrNotFound, ErrUnsupported.
	ListSnapshots(ctx context.Context, volID string) ([]SnapshotInfo, error)

	// DeleteSnapshot removes the snapshot; ErrSnapshotNotFound, ErrUnsupported. A provider may refuse when restored volumes depend on it.
	DeleteSnapshot(ctx context.Context, snapID SnapshotID) error

	// Delete removes the volume; ErrNotFound, or ErrHasSnapshots, since it never cascades.
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
