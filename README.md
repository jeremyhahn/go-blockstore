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
  matching build tags. The concrete providers ship in follow-up work (local #2,
  drbd #3, ha #4) — until then this scaffold is the registry alone, and
  `NewProvider` has nothing to hand back for any name.
- **Injected Coordinator** (`pkg/common`) — the `Coordinator` and `Lease`
  interfaces are declared here, not imported from a concrete consensus store, so
  the library never depends on go-qrdb or go-quicraft directly. Callers inject a
  coordinator implementation; dependency inversion keeps the coordination
  substrate a deployment choice while still enabling leader election, metadata
  storage and change notification for HA volumes.

## Layout

```
pkg/
  common/    interfaces, value types, sentinel errors, injected Coordinator
  factory/   name-keyed provider registry (thread-safe), build-tag convention
```
