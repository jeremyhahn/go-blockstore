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

	// ReplStateInconsistent indicates the volume is connected and replicating
	// normally, but the LOCAL copy is not current — mid-resync, outdated,
	// failed, or without a backing device at all.
	//
	// It is distinct from ReplStateUnknown, and the distinction is the point: a
	// controller deciding whether to promote must tell "the local copy is known
	// to be bad" from "the state could not be determined". Both forbid
	// promotion, but only the first is a fact about the volume.
	//
	// It does not say WHY the copy is not current. A provider that can
	// distinguish an inconsistent disk from an absent one reports the
	// difference through VolumeStatus.State, which has VolumeStateError for a
	// device that cannot serve reads at all.
	ReplStateInconsistent ReplConnState = "inconsistent"

	// ReplStateDown indicates the volume is configured for replication but is
	// not running it — the resource exists and the provider knows about it, and
	// nothing is up.
	//
	// It sits between the two states it is easily confused with.
	// ReplStateStandalone means the volume IS up and has stopped talking to its
	// peer, which is an operator-visible decision; ReplStateUnknown means the
	// provider could not determine anything. Down is neither: it is a definite
	// answer, and the answer is that replication is not happening.
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

// VolumeSpec describes a volume to be provisioned.
//
// Name and FSType are free-form: this package constrains neither, so the
// provider validates both before they reach a system tool. See the
// VolumeProvider doc for the rule.
type VolumeSpec struct {
	// Name is a human-readable identifier for the volume. It is caller-supplied
	// and unvalidated here; the provider validates it before using it to name a
	// logical volume or resource.
	Name string

	// SizeBytes is the requested capacity of the volume in bytes, and it means
	// the capacity THE CALLER CAN USE. A provider that needs room for its own
	// per-volume structures — a LUKS2 header, DRBD's internal metadata —
	// allocates that ON TOP, so the backing device it creates is larger than
	// this number and the space this number describes is all available to the
	// caller.
	//
	// The rule exists because the alternative cannot be written down once. If
	// SizeBytes sized the backing device instead, every caller would have to
	// know which backend it had reached and how much that backend skims off
	// the front or the back — and would get it wrong silently, since a volume
	// asked for at exactly the size of the data destined for it would come
	// back too small only when the data arrived. Overhead is the provider's
	// business, and the provider is the only party that knows it.
	//
	// Backends allocating in fixed units round up, so the usable capacity can
	// exceed this. It is never below it.
	SizeBytes int64

	// StorageClass names the provider-specific class/tier backing the volume.
	StorageClass string

	// Replicas is the desired number of replicas, in three branches:
	//
	// Zero means UNSPECIFIED, and the provider uses its natural count — one for
	// a local volume, two for a replicated pair. It does not mean one. A caller
	// that leaves the field alone is asking for whatever the provider it chose
	// is for, not asserting that the volume must not be replicated.
	//
	// A negative value is never meaningful and returns ErrInvalidArgument.
	//
	// A positive value the provider cannot honor returns ErrUnsupported, not
	// ErrInvalidArgument: asking a two-node replication backend for a single
	// copy is a well-formed request that a different backend serves happily, so
	// the answer is "choose another provider", which is what ErrUnsupported
	// means and what ErrInvalidArgument would hide.
	Replicas int

	// FSType is the filesystem to create on the volume (e.g. "ext4", "xfs").
	// An empty value requests a raw, unformatted block device. The provider
	// checks it against the filesystems it supports rather than passing it
	// through to mkfs unexamined.
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

	// SizeBytes is the current capacity of the volume in bytes, in the same
	// units VolumeSpec.SizeBytes is requested in: the capacity the CALLER CAN
	// USE, with the provider's own overhead already subtracted. It is
	// comparable against the size the volume was provisioned or resized to, and
	// is at least that much.
	//
	// Reporting the backing device here instead would make Status disagree with
	// Provision about what one volume's size is — a caller that asked for a
	// gibibyte would read back a gibibyte plus a header and have no way to tell
	// that apart from a volume somebody had grown.
	//
	// A provider that cannot determine its overhead for a volume in the state
	// it is currently in documents what it reports instead; see the provider's
	// own Status doc.
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

	// Flags carries additional mount flags (e.g. "noatime"). They are
	// free-form and unvalidated here; because they end up as arguments to
	// mount, the provider validates each against the flags it allows before
	// passing them on. See the VolumeProvider doc for the rule.
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
