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

import "time"

// NodeID uniquely identifies a node in the cluster on which a volume can be
// attached, mounted, or replicated.
type NodeID string

// SnapshotID uniquely identifies a point-in-time snapshot of a volume.
type SnapshotID string

// VolumeState describes the lifecycle state of a provisioned volume.
type VolumeState string

const (
	// VolumeStateUnknown indicates the volume state could not be determined.
	VolumeStateUnknown VolumeState = "unknown"

	// VolumeStateProvisioning indicates the volume is being created.
	VolumeStateProvisioning VolumeState = "provisioning"

	// VolumeStateAvailable indicates the volume exists and is not attached.
	VolumeStateAvailable VolumeState = "available"

	// VolumeStateAttached indicates the volume is attached to at least one node.
	VolumeStateAttached VolumeState = "attached"

	// VolumeStateMounted indicates the volume is mounted on at least one node.
	VolumeStateMounted VolumeState = "mounted"

	// VolumeStateDeleting indicates the volume is being deleted.
	VolumeStateDeleting VolumeState = "deleting"

	// VolumeStateError indicates the volume is in an error state.
	VolumeStateError VolumeState = "error"
)

// ReplRole is the replication role a node holds for a replicated volume.
type ReplRole string

const (
	// ReplRoleUnknown indicates the replication role could not be determined.
	ReplRoleUnknown ReplRole = "unknown"

	// ReplRolePrimary indicates the node holds the primary (read/write) copy.
	ReplRolePrimary ReplRole = "primary"

	// ReplRoleSecondary indicates the node holds a secondary (replica) copy.
	ReplRoleSecondary ReplRole = "secondary"
)

// ReplConnState describes the connection/synchronization state of a replicated
// volume, modeled on the states a DRBD-style replicated device moves through.
type ReplConnState string

const (
	// ReplStateUnknown indicates the replication state could not be determined.
	ReplStateUnknown ReplConnState = "unknown"

	// ReplStateStandalone indicates the volume is not connected to any peer.
	ReplStateStandalone ReplConnState = "standalone"

	// ReplStateConnecting indicates the volume is establishing a peer connection.
	ReplStateConnecting ReplConnState = "connecting"

	// ReplStateSyncSource indicates the volume is the source of an in-progress sync.
	ReplStateSyncSource ReplConnState = "sync-source"

	// ReplStateSyncTarget indicates the volume is the target of an in-progress sync.
	ReplStateSyncTarget ReplConnState = "sync-target"

	// ReplStateUpToDate indicates the volume is connected and fully synchronized.
	ReplStateUpToDate ReplConnState = "uptodate"

	// ReplStateInconsistent means replication is up but the local copy is not current; promotion is forbidden.
	ReplStateInconsistent ReplConnState = "inconsistent"

	// ReplStateDown means the volume is configured for replication but replication is not running.
	ReplStateDown ReplConnState = "down"
)

// EventType classifies a coordinator Watch event.
type EventType string

const (
	// EventTypePut indicates a key was created or updated.
	EventTypePut EventType = "put"

	// EventTypeDelete indicates a key was deleted.
	EventTypeDelete EventType = "delete"
)

// VolumeSpec describes a volume to be provisioned; the provider validates Name and FSType.
type VolumeSpec struct {
	// Name is a human-readable identifier for the volume. It is caller-supplied
	// and unvalidated here; the provider validates it before using it to name a
	// logical volume or resource.
	Name string

	// SizeBytes is the usable capacity requested; provider overhead is allocated on top, and the result is never below it.
	SizeBytes int64

	// StorageClass names the provider-specific class/tier backing the volume.
	StorageClass string

	// Replicas is the desired replica count: 0 uses the provider's natural count, negative is ErrInvalidArgument, unsupported is ErrUnsupported.
	Replicas int

	// FSType is the filesystem to create (e.g. "ext4", "xfs"); empty requests a raw block device.
	FSType string

	// SourceSnapshotID provisions the volume from an existing snapshot when
	// non-empty, giving it that snapshot's contents. The zero value provisions
	// an empty volume. See VolumeProvider.Provision for the restore contract.
	SourceSnapshotID SnapshotID

	// Labels carries arbitrary provider- or caller-defined metadata.
	Labels map[string]string
}

// Volume identifies a provisioned volume together with the spec it was created
// from.
type Volume struct {
	// ID is the provider-assigned unique identifier for the volume.
	ID string

	// Spec is the specification the volume was provisioned from.
	Spec VolumeSpec
}

// VolumeStatus reports the current observed state of a volume.
type VolumeStatus struct {
	// ID is the provider-assigned unique identifier for the volume.
	ID string

	// State is the current lifecycle state of the volume.
	State VolumeState

	// SizeBytes is the usable capacity in bytes, provider overhead already subtracted, as in VolumeSpec.SizeBytes.
	SizeBytes int64

	// AttachedNodes lists the nodes the volume is currently attached to.
	AttachedNodes []NodeID

	// Replication reports the replication state; the zero value is meaningful
	// for non-replicated volumes.
	Replication ReplState
}

// SnapshotInfo describes a point-in-time snapshot of a volume, as reported by
// VolumeProvider.ListSnapshots.
type SnapshotInfo struct {
	// ID is the provider-assigned unique identifier for the snapshot — the
	// value Snapshot returned, and the one DeleteSnapshot and
	// VolumeSpec.SourceSnapshotID take.
	ID SnapshotID

	// VolumeID identifies the volume the snapshot was taken from.
	VolumeID string

	// Name is the caller-supplied name the snapshot was created with.
	Name string

	// CreatedAt is the time the snapshot was taken.
	CreatedAt time.Time

	// SizeBytes is the size of the snapshot in bytes. Providers using
	// copy-on-write snapshots report the space the snapshot occupies, which
	// grows as the source volume diverges and is not the volume's capacity.
	SizeBytes int64
}

// AttachInfo describes the result of attaching a volume to a node.
type AttachInfo struct {
	// DevicePath is the local block-device path on the node (e.g. "/dev/drbd0").
	DevicePath string

	// Node is the node the volume was attached to.
	Node NodeID
}

// MountOptions controls how a volume is mounted.
type MountOptions struct {
	// ReadOnly requests a read-only mount.
	ReadOnly bool

	// FSType overrides the filesystem type used for the mount. An empty value
	// uses the volume's provisioned filesystem.
	FSType string

	// Flags carries additional mount flags (e.g. "noatime"); the provider validates each against its allowlist.
	Flags []string
}

// ReplState reports the replication status of a volume.
type ReplState struct {
	// Conn is the connection/synchronization state.
	Conn ReplConnState

	// Role is the replication role held locally for the volume.
	Role ReplRole

	// Peer identifies the replication peer, when connected.
	Peer NodeID
}

// Event is a change notification delivered over a Coordinator Watch channel.
type Event struct {
	// Type classifies the change.
	Type EventType

	// Key is the affected key.
	Key string

	// Value is the new value for put events; nil for delete events.
	Value []byte
}
