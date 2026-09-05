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

// Package drbd implements common.ReplicatedProvider over DRBD 9, giving
// go-blockstore synchronously replicated block volumes on a two-node pair.
//
// The package is gated behind the "drbd" build tag: every file except this one
// carries //go:build drbd, so a binary built without the tag compiles an empty
// package, links no DRBD tooling and never sees "drbd" from
// factory.ListProviders. Registration lives in pkg/factory/factory_drbd.go,
// under the same tag, following the convention in that package's doc.
//
// # drbdadm, not LINSTOR
//
// DRBD can be driven two ways: directly through drbdadm/drbdsetup against
// per-resource configuration files, or through LINSTOR, which manages resource
// placement across a cluster from a controller daemon plus a satellite on every
// node.
//
// This provider drives drbdadm directly. LINSTOR earns its keep when resources
// must be placed and rebalanced across a changing pool of nodes; the target
// here is a fixed two-node HA pair whose placement is decided by configuration,
// not scheduled. Adopting LINSTOR would add a controller daemon (itself a
// single point of failure needing its own HA story), a satellite on both nodes,
// a database, and a second source of truth for state that the HA controller in
// issue #4 already keeps in the injected Coordinator. drbdadm needs none of
// that: the kernel module, drbd-utils, and a generated .res file per volume.
//
// The cost of the choice is that this provider owns resource-file generation,
// minor/port allocation and status parsing itself — which is what the code
// below is. If go-blockstore ever targets a scheduled, many-node pool, LINSTOR
// becomes the better substrate and belongs behind a separate provider name
// rather than as a mode of this one.
//
// # What this provider is, and is not
//
// It is the mechanical layer: it creates backing logical volumes, generates and
// installs DRBD resource configuration, brings resources up and down, and
// exposes Promote, Demote and ReplicationState. It does not talk to a
// common.Coordinator and holds no leases. The HA controller (issue #4) owns the
// per-volume primary lease and calls Promote only while it holds that lease.
// Keeping the lease out of here means the promotion path has exactly one
// gatekeeper.
//
// # Force-primary is deliberately absent
//
// Promote runs "drbdadm primary <res>" and never "drbdadm primary --force".
// The provider exposes no ForceOutOfSync, no split-brain override, and no
// setting that turns one on.
//
// A regular promotion is refused by DRBD precisely when promoting would be
// unsafe: the local disk is not UpToDate, or the peer holds Primary. --force
// overrides that check and promotes an Inconsistent or diverged copy, which
// makes the local data authoritative and discards whatever the peer has. That
// is a data-loss decision. It depends on facts this library cannot see — which
// node was writing when the link broke, which copy the operator wants to keep,
// whether the peer is down or merely unreachable — and it is exactly the
// decision a split-brain runbook exists to make.
//
// So the refusal is the feature. A library default that silently force-promotes
// turns a recoverable split brain into a destroyed replica. Forcing belongs to
// the HA controller acting on an explicit operator decision, invoking drbdadm
// out of band; when the controller grows a supervised recovery path it will
// carry its own audit trail and confirmation, neither of which a VolumeProvider
// method can express.
//
// The same reasoning does not apply to "drbdadm -- --force create-md", which
// Provision does run. That force initializes DRBD metadata on a backing device
// this provider created moments earlier, suppressing a confirmation prompt
// about data that is ours to overwrite. It destroys nothing a caller has.
//
// # Initial sync is not performed
//
// Provision leaves a new resource up, Secondary on both nodes, and Inconsistent
// — DRBD's correct state for a resource whose two copies have never agreed.
// Making one side authoritative for the first time ("drbdadm primary --force",
// or "drbdadm new-current-uuid --clear-bitmap" to skip the full sync) is the
// same class of decision as force-promotion and is left to the HA controller
// and the operator. A freshly provisioned volume therefore cannot be promoted
// until that step is taken.
//
// # A resource is provisioned on both nodes, and three values must match
//
// This provider drives the local DRBD instance. It has no channel to the peer,
// so provisioning a replicated volume means running Provision on both nodes,
// and the two resource files they write have to describe the same resource.
//
// Three values are shared rather than local, because DRBD writes them at
// resource scope: the device minor, the replication port, and the mapping from
// node name to node id. The node ids need no coordination — with neither given
// they are derived by sorting the two node names, so both hosts reach the same
// assignment on their own. The minor and the port are allocated from the local
// state directory, which is correct for a pair kept in step by hand and wrong
// the moment those directories drift, so a caller that coordinates the pair
// pins both through the LabelMinor and LabelPort labels on the VolumeSpec. The
// HA controller, which holds the Coordinator and can allocate cluster-wide, is
// that caller.
//
// # Snapshots are LVM snapshots of the backing device
//
// DRBD has no snapshot facility of its own, so Snapshot takes an LVM snapshot
// of the backing logical volume underneath the replicated device.
//
// Two consequences follow, both enforced rather than documented away. A
// snapshot is only meaningful on the node holding Primary, because the
// Secondary's backing device receives replicated writes with no filesystem
// consistency point above it; Snapshot returns common.ErrUnsupported on a
// Secondary. And a snapshot taken while the volume is Primary and in use is
// crash-consistent, not application-consistent: it captures the block device as
// a power cut would, so a journaling filesystem replays cleanly but an
// application with unflushed state does not. Quiescing the workload before
// snapshotting is the caller's job.
//
// The snapshot is local to the node that took it. It is not replicated to the
// peer and does not survive that node's loss.
//
// # Security posture
//
// Mounting does not go through the command runner. A mount target has to be
// PINNED — resolved to a descriptor with symlink resolution refused, and
// mounted against the descriptor — because validating a path and then handing
// the string to mount(8) leaves a window in which the path can become a
// symlink, and the privileged mount that follows lands wherever it points.
// That is internal/mount, shared with pkg/local rather than reimplemented here:
// a security-relevant mechanism duplicated per provider is one that drifts per
// provider.
//
// Every other value that reaches a system tool is validated against an
// allowlist first, and passed as a separate argv element to an exec'd binary —
// no shell, ever. Volume and snapshot names, filesystem types, mount flags and mount
// targets are checked in validate.go; resource files are rendered from a
// text/template whose inputs are typed integers and already-validated strings,
// so a hostile VolumeSpec.Name cannot inject DRBD configuration.
//
// # Mount propagation, and what Posture is for
//
// A mount made here is invisible to a workload in another mount namespace
// unless it propagates, and nothing reports that: mount(2) succeeds, this
// provider reports success, and the workload finds the directory as it was.
// mount_propagation=shared makes Mount verify the mount it just made and refuse
// a private one, unwinding it rather than leaving a filesystem the caller was
// told did not appear. The check is internal/mountguard, shared with pkg/local
// for the reason internal/mount is.
//
// It is OFF by default, because a replicated cluster whose mounts nobody
// consumes from another namespace is not broken and should not start failing on
// upgrade. An off guard is an invisible one, so Provider.Posture names every
// guard this provider has and whether it is checked — including the ones that
// are not — for a component to print once at startup.
//
// # Peer authentication, and what the resource file is worth
//
// Generated resources authenticate the peer with cram-hmac-alg sha256 and a
// shared secret. Without it, DRBD accepts whoever connects on the replication
// address: a VLAN is segmentation, not identity, and anything that can reach
// the address and speak the protocol can present itself as the other node —
// read the volume, or feed it writes. CRC32C, which the resource also sets, is
// integrity against corruption and not against anybody.
//
// The secret reaches this package as a locked enclave through a SecretProvider,
// and is borrowed for exactly one thing: rendering the resource file. It exists
// as a Go string only inside that callback.
//
// And then it is on disk, because DRBD reads it from the configuration drbdadm
// parses. There is no key file, no agent, no indirection DRBD offers. That
// constraint is DRBD's design and this package cannot route around it; what it
// can do is not pretend otherwise:
//
//   - The .res file is worth what a LUKS key file is worth. It is written 0600
//     in a directory this package creates 0750, and anything that reads it can
//     impersonate a node of the pair.
//   - Rotation is regenerate-and-adjust, on BOTH nodes: change the secret
//     source, regenerate the resource files, and run "drbdadm adjust" on each.
//     A pair with mismatched secrets does not authenticate, so this is a
//     coordinated operation and not a rolling one.
//   - Backups of /etc/drbd.d carry the secret. So do configuration-management
//     systems that template the directory.
//
// The secret is also the ONE value in a generated resource file that cannot be
// checked against an allowlist of shapes — every other input is a name, a
// hostname or an address, and a secret is arbitrary by definition. Since it is
// written inside a quoted string, a secret carrying a quote and a newline would
// close the string and have what followed parsed as DRBD directives. It is
// therefore checked against a character set: printable ASCII, no space, no
// quote, no backslash, within DRBD's 64-byte limit. That constrains what an
// operator may choose and not how much entropy they get.
//
// A resource can be provisioned with no authentication at all, and only
// deliberately: allow_unauthenticated_peers=true, absent by default, refused
// alongside a secret, and named so nobody sets it mistaking it for a tuning
// knob. The resource file it produces says in a comment that nothing is
// authenticating the peer, so the state is visible on the node and not only in
// whatever provisioned it.
//
// # Confidentiality in transit
//
// Replication is NOT encrypted. An unauthenticated peer is now refused, but the
// block data itself crosses the storage VLAN as plaintext, and a shared secret
// authenticates the peer without concealing anything from something that can
// observe the link.
//
// This is stated rather than solved here. The standard answer is dm-crypt ABOVE
// the replicated device, so the wire carries ciphertext and a failover unlocks
// on the new Primary — the same layering pkg/local applies to a logical volume.
// It is not yet implemented in this provider; see the report on issue #3.
package drbd
