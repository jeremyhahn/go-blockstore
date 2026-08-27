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
  matching build tags. `drbd` (#3) and `ha` (#4) are still to come.
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

## Layout

```
pkg/
  common/    interfaces, value types, sentinel errors, injected Coordinator
  factory/   name-keyed provider registry (thread-safe), build-tag convention
  local/     always-compiled LVM + LUKS2 provider (no build tag)
```

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
