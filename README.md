# go-blockstore

Embedded block/volume storage library — pluggable providers (DRBD, Ceph-RBD, local) with lease-coordinated HA. Foundational sibling to go-objstore.

## Role

Where go-objstore is the object-storage library of the trusted computing stack,
go-blockstore is its block/volume sibling. It manages the lifecycle of block
volumes — provisioning, attaching them to nodes as block devices, mounting,
resizing, snapshotting, deletion — behind a single provider interface, and adds
the promote/demote and replication-state operations needed to run replicated
(primary/secondary) volumes for high availability.

The library is built from three pieces:

- **Interfaces** (`pkg/common`) — `VolumeProvider` is the contract every backend
  implements; `ReplicatedProvider` extends it with the replication operations
  (`Promote`, `Demote`, `ReplicationState`) that HA volumes require. The value
  types (`VolumeSpec`, `VolumeStatus`, `AttachInfo`, `MountOptions`, `ReplState`,
  and friends) and the sentinel errors live here too.
- **Providers + registry** (`pkg/factory`) — backends self-register by name via
  `RegisterProvider`, typically from an `init` in a build-tag-gated file so
  unused backends and their system/kernel dependencies are not linked in. A
  provider is created on demand with `NewProvider(name, settings)`. By
  convention the `local` provider carries no build tag and is always compiled,
  while networked/kernel-backed providers (`drbd`, `cephrbd`) are gated behind
  matching build tags. `cephrbd` is still to come.
- **Local provider** (`pkg/local`) — the always-compiled backend, over LVM and
  optional LUKS2 on a single host. A volume is a logical volume in one volume
  group; `Attach` activates it and unlocks its LUKS container when it has one,
  so callers get a mountable device path either way. It keeps no state of its
  own — every answer is read back from `lvs`, `blkid` and `findmnt` — and every
  system command goes through an injectable `CommandRunner`, which is what makes
  the backend unit-testable without root or a block device. LUKS passphrases
  arrive through a `KeyProvider` callback as a
  [go-enclave](https://github.com/jeremyhahn/go-enclave) `MemoryEnclave` — mlock'd,
  guard-paged, wiped on release — and become a `[]byte` only inside the borrow
  that writes them to `cryptsetup`'s stdin, never on a command line. If the
  kernel will not lock memory the operation fails naming `RLIMIT_MEMLOCK`
  rather than falling back to unprotected memory. Where the key came from (a
  file, an operator, a TPM-sealed blob) is the caller's business. Needs LVM 2.03.12+, and `cryptsetup` only when
  encryption is in use.
- **Serialization** — every state-changing operation holds a per-volume `flock`
  under `lock_dir` for its whole read-decide-act sequence, so two operations
  cannot interleave and act on a world that moved. Because it is a file lock
  rather than a mutex, it holds across separate `Provider` values and across
  separate processes on the host, and the kernel releases it if one dies.
- **Injected Coordinator** (`pkg/common`) — the `Coordinator` and `Lease`
  interfaces are declared here, not imported from a concrete consensus store, so
  the library never depends on go-qrdb or go-quicraft directly. Callers inject a
  coordinator implementation; dependency inversion keeps the coordination
  substrate a deployment choice while still enabling leader election, metadata
  storage and change notification for HA volumes.
- **HA controller** (`pkg/ha`) — the only consumer of the injected
  `Coordinator`. It campaigns for a per-volume primary lease, promotes the local
  copy while it holds one, and stops acting the moment it loses one. It is
  constructed with the provider and the Coordinator passed explicitly, because
  providers are mechanical and need no Coordinator; putting the lease behind the
  factory's name lookup would give every backend a dependency exactly one caller
  uses.

## Layout

```
pkg/
  common/    interfaces, value types, sentinel errors, injected Coordinator
  factory/   name-keyed provider registry (thread-safe), build-tag convention
  local/     always-compiled LVM + LUKS2 provider (no build tag)
  drbd/      DRBD 9 replicated provider (build tag: drbd)
  ha/        lease-based HA controller — promote/demote/fence, no build tag
```

## High availability

`pkg/ha` runs one controller per node. Each managed volume gets its own lease
key and its own goroutine; the holder promotes the local copy and renews at a
third of the TTL, and a lost lease fences that volume immediately — including
cancelling a promotion already in flight.

Two things about it are worth reading before deploying it, and both are spelled
out in full in the package documentation:

- **The lease is a control-plane fence, not a data-plane fence.** Losing it
  makes the controller stop acting. It does not make the kernel stop accepting
  writes to a device that is already Primary and already mounted, so a node that
  is partitioned rather than dead keeps writing while its peer takes over.
  Closing that gap needs DRBD's own `fencing resource-and-stonith` with a fence
  agent, or quorum. A lease is coordination; a fence is a power switch.
- **Only an `uptodate` local copy is promoted.** Every other replication state
  is refused with a reason, `sync-source` included — that bucket says the peer
  is behind, not that the local disk is current. The controller never forces a
  promotion: DRBD's refusal of a stale one is a feature it surfaces.

The controller drives `Promote` and `Demote` and nothing else. Mounting is the
workload orchestrator's step, taken after `Config.Observer` reports that this
node became primary; unmounting is what makes the demote on the way back out
possible.

### The Coordinator must be able to lease

In every deployment, clustered or not. The `Coordinator` contract lets an
implementation without consensus reject `AcquireLease` and `Watch` as "not
supported" while still serving the key/value family, and go-qrdb is such an
implementation — its lease and watch families are raft-only. `pkg/ha` does not
carry a second, CAS-based arbitration path for that case, because the promotion
path has exactly one gatekeeper and a second mechanism selected by
configuration is a second thing to get wrong on the path where wrong means two
nodes writing to one device.

So the deployment supplies a Coordinator that leases:

- **Clustered** — go-qrdb in raft mode. The lease means cross-node ownership
  arbitrated by a quorum. This is the only configuration in which a replicated
  pair managed from *both* of its nodes is safe.
- **Single-node** — an in-process Coordinator serving the whole contract without
  raft (go-trusted-platform's `pkg/storage/coordination.Local`). It arbitrates
  among the goroutines of one process and its guarantees stop at the process
  boundary. It does **not** protect a replicated pair whose two nodes each run
  their own control plane: two processes sharing neither map nor leases would
  both acquire "the" lease and both promote.

A Coordinator that cannot lease is not specially detected — "not supported" is
implementation-defined — so it surfaces as an ordinary operational failure and
the controller promotes nothing. A volume that never leaves `campaigning` is the
symptom.

Deployment caveat: an **embedded** go-qrdb coordinator (go-qrdb #174) never
reaps an expired lease's key, so it fences but never re-elects. Run a
coordinator backend whose lease sweeper is running.

Nothing in `pkg/ha` has been run against real DRBD or a real two-node pair; it
is verified against the contracts its dependencies publish. Read it as
contract-validated, not hardware-validated, failover.

## Testing

`go test ./...` runs the whole suite against fakes — no root, no LVM, no block
devices. The tests that drive real LVM, LUKS and filesystems are selected by a
build tag rather than skipped at run time, so a suite that cannot run fails
instead of quietly passing:

```
sudo -E go test -tags local_integration -race ./pkg/local/
```

They build their own volume group on a loopback file and tear it down again.
They need root and the `lvm2`, `cryptsetup`, `e2fsprogs` and `util-linux`
tooling.
