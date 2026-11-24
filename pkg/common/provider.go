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
// line, and a value that fails validation is rejected rather than escaped and
// passed on — with ErrInvalidArgument, wrapped with the detail saying which
// value and why, and before the provider has run anything.
type VolumeProvider interface {
	// Provision creates a new volume matching the given spec and returns the
	// resulting Volume. It returns ErrAlreadyExists if a volume with the same
	// identity already exists.
	//
	// spec.SizeBytes is USABLE capacity, not the size of the device the
	// provider allocates to hold it: a provider with per-volume overhead of its
	// own adds that on top. See VolumeSpec.SizeBytes.
	//
	// A non-empty spec.SourceSnapshotID provisions the volume from that
	// snapshot rather than empty, giving the new volume the snapshot's
	// contents; it returns ErrSnapshotNotFound if no such snapshot exists. The
	// rest of the spec still applies — notably spec.SizeBytes, which must be at
	// least the snapshot's USABLE size, since a provider is not required to
	// support shrinking during restore and returns ErrUnsupported if asked to.
	// Comparing against the snapshot's usable size rather than its image size
	// is what keeps the restore threshold in the same units as the request: on
	// a backend with overhead the two differ by exactly that overhead, and a
	// caller that read a volume's size from Status can hand the same number
	// back here.
	Provision(ctx context.Context, spec VolumeSpec) (Volume, error)

	// Attach makes the volume available as a block device on the given node and
	// returns the resulting AttachInfo. It returns ErrNotFound if the volume
	// does not exist.
	//
	// A well-formed request naming a node this provider cannot serve returns
	// ErrUnsupported, wrapped with detail identifying the node and why it is out
	// of reach. The request is not wrong — a different backend could serve it,
	// and the caller placing the workload is the one that knows the topology —
	// so it is reported as a capability this provider lacks rather than as a bad
	// argument. A single-host backend answers this way for every node but its
	// own; a replicated one only for nodes outside the set it replicates to.
	//
	// A node that is not merely unreachable but meaningless to the backend —
	// absent from its configuration entirely — is ErrInvalidArgument instead,
	// because no amount of choosing a different provider makes that name valid.
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

	// Resize grows the volume to newSize bytes of USABLE capacity, in the same
	// units VolumeSpec.SizeBytes and VolumeStatus.SizeBytes use — a provider
	// with per-volume overhead grows the backing device by more than the
	// difference, so that the caller ends up with the capacity it named. It
	// returns ErrNotFound if the volume does not exist. Providers are not
	// required to support shrinking; a newSize below the current capacity
	// returns ErrUnsupported on a provider that cannot shrink.
	//
	// Resize grows the block device, and it grows the filesystem too when the
	// volume was provisioned with an FSType the provider knows and that
	// filesystem can be grown in the state the volume is currently in — ext2,
	// ext3 and ext4 mounted or not; XFS only while mounted, having no offline
	// grow. Where the filesystem cannot be grown as things stand, the device is
	// still grown and the call still succeeds; the provider documents the state
	// that leaves behind, so an operator knows an unmounted XFS volume needs
	// growing after its next mount. A raw volume has nothing to grow but itself.
	//
	// Growing what sits on top of the device is part of the operation, not a
	// separate one, so a provider whose device growth succeeded and whose
	// filesystem growth did not must let a repeat of the same request finish the
	// job. Treating an already-large-enough device as nothing to do would report
	// success over a filesystem still at its old size.
	//
	// Backends that allocate in fixed units may round newSize up, so the volume
	// can end up larger than asked for. It is never smaller, and a provider
	// compares against the rounded figure when deciding whether a request is a
	// shrink — otherwise repeating a request it has already rounded up looks
	// like one.
	Resize(ctx context.Context, volID string, newSize int64) error

	// Snapshot creates a named point-in-time snapshot of the volume and returns
	// its SnapshotID. It returns ErrNotFound if the volume does not exist,
	// ErrAlreadyExists if the volume already has a snapshot by that name, and
	// ErrUnsupported on a provider without snapshot support.
	//
	// A replicated provider returns ErrNotPrimary when the local node holds the
	// secondary role. A secondary's backing device receives the replication
	// stream with no filesystem above it ordering those writes, so a snapshot
	// of one captures a state no filesystem ever had — and the condition is
	// fixed by a Promote, which is what ErrNotPrimary says and what
	// ErrUnsupported would deny.
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
	// volume does not exist, and ErrHasSnapshots if the volume still has
	// snapshots.
	//
	// It does not cascade. A provider whose snapshots cannot outlive their
	// origin — LVM copy-on-write snapshots, among others — would destroy them
	// as a side effect of removing the volume, so it refuses instead and the
	// caller deletes them first. Losing a restore point is a decision worth
	// making out loud.
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
