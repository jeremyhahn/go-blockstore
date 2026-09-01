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
  the backend unit-testable without root or a block device. LUKS is done in
  pure Go by [go-luks2](https://github.com/jeremyhahn/go-luks2) — headers are
  written and parsed in-process and the plaintext mapping is created with
  device-mapper ioctls — so **no `cryptsetup` binary is forked or needs to be
  installed**. LUKS passphrases arrive through a `KeyProvider` callback as a
  [go-enclave](https://github.com/jeremyhahn/go-enclave) `MemoryEnclave` — mlock'd,
  guard-paged, wiped on release — and become a `[]byte` only inside the borrow
  that hands them to go-luks2 for one call; they never leave the process, and
  never appear on a command line. If the kernel will not lock memory the
  operation fails naming `RLIMIT_MEMLOCK` rather than falling back to
  unprotected memory. Where the key came from (a file, an operator, a
  TPM-sealed blob) is the caller's business. Needs LVM 2.03.12+.
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
  preflight/ startup privilege checks — probes device-mapper, mount(2) and the
             kernel keyring, and refuses a deployment that cannot serve them
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

## Deployment: privilege belongs in ONE component

Attaching an encrypted volume needs privilege. That privilege belongs in exactly
one small, audited component — a control plane, an init container, a CSI node
plugin — which unseals the key, attaches the LUKS volume, mounts the filesystem,
and hands the **already-mounted filesystem** to the workload.

```
  ┌─────────────────────────────┐        ┌──────────────────────────┐
  │ storage component           │        │ workload container       │
  │ (control-plane / init /     │        │                          │
  │  CSI node plugin)           │        │  NO capabilities         │
  │                             │        │  NO seccomp exception    │
  │  CAP_SYS_ADMIN              │───────▶│  NO device access        │
  │  seccomp: default + 3       │ mount  │  NEVER sees the key      │
  │  /dev/mapper/control        │        │                          │
  │  the block device           │        │  just a mounted fs       │
  └─────────────────────────────┘        └──────────────────────────┘
```

**The workload's requirements are none.** No capabilities, no seccomp exception,
no device access, no key. It receives a directory. A deployment that finds itself
granting the workload `CAP_SYS_ADMIN` has the shape wrong.

**The storage component's minimum**, measured rather than assumed:

| Requirement | Why | Docker | Kubernetes |
|---|---|---|---|
| `CAP_SYS_ADMIN` | device-mapper ioctls, `mount(2)` | `--cap-add SYS_ADMIN` | `securityContext.capabilities.add: ["SYS_ADMIN"]` |
| seccomp: default **+ `add_key`, `keyctl`, `request_key`** | the volume key reaches dm-crypt as a keyring reference | `--security-opt seccomp=<profile>.json` | `securityContext.seccompProfile` (localhost) |
| an LSM profile permitting `mount(2)` | the default AppArmor profile denies it | `--security-opt apparmor=<profile>` | node-level profile |
| `/dev/mapper/control` | the device-mapper control node | `--device /dev/mapper/control` (**not** a bind mount) | the node must be **allowed**, not merely mounted in |
| the specific block device | and nothing else under `/dev` | `--device <path>` | `hostPath` |

**Never `--privileged`.** It grants every capability, disables the seccomp
profile *and* the LSM confinement wholesale, and exposes every host device, so it
replaces a bounded grant with an unbounded one. It is not the fix for any refusal
this library reports.

### The three mechanisms are independent, and that is the trap

Capabilities, seccomp and LSM confinement are enforced by different subsystems,
granting one does not lift another, and all three surface as a bare "operation
not permitted". Measured 2026-09-01 in a container with `--cap-add SYS_ADMIN` and
`--device /dev/mapper/control` under Docker's **default** profiles:

| | verdict |
|---|---|
| device-mapper | **works** — `DM_VERSION` returns interface version 4.48.0 |
| kernel keyring | **BLOCKED** — seccomp denies `add_key`/`keyctl`/`request_key` |
| `mount(2)` | **BLOCKED** — the default AppArmor profile denies it |

So an operator grants `CAP_SYS_ADMIN`, watches device-mapper work, and concludes
the container is correctly privileged. The keyring failure arrives later, under
load, in a path that looks like a storage fault rather than a container-config
fault.

### The guard

`pkg/preflight` probes each mechanism separately, at startup, and refuses with an
error naming which one is missing and the exact remedy. `local.New` runs it for
the capabilities the configuration implies, so a provider constructed in a
misconfigured container is not constructed at all:

```go
// explicitly, in a storage component's initialization
err := preflight.Check(ctx,
    preflight.CapabilityDeviceMapper,
    preflight.CapabilityMount,
    preflight.CapabilityKernelKeyring)
```

Every check **attempts the operation**; nothing reads `CapEff` and reasons about
it, because that reports full confidence in exactly the container above. Where
one errno has two possible causes — `mount(2)` answers `EPERM` both for a
missing `CAP_SYS_ADMIN` and for a seccomp denial — the guard asks the kernel to
*demonstrate* the capability through a device-mapper ioctl rather than guessing,
and where that witness is out of reach it reports the ambiguity and names both
fixes. A probe
that cannot establish an answer **fails** rather than passing — an empty
capability list and an unregistered capability are failures too.

The `preflight` setting (`configured`, `all`, `off`) selects the mode through
the factory. `off` exists for a process that constructs a provider it will not
perform privileged operations with; it is an explicit, reviewable line in
configuration and never a default.

### Verifying it

```
make preflight-matrix     # needs Docker; asserts, does not merely print
```

It starts eleven containers and checks the guard refuses each misconfigured one —
including the `CAP_SYS_ADMIN`-with-default-seccomp trap — and **passes** the one
with a narrow seccomp profile that adds the three syscalls. That passing row is
what keeps this from being a guard that refuses everything.

The refusals are distinguished, because they have different fixes and one errno
is not enough to tell them apart:

| What is actually wrong | How the guard tells | Cause |
|---|---|---|
| the node is not in this namespace | `open` → `ENOENT` | `device-missing` |
| the node is visible but not **allowed** (bind-mounted instead of `--device`) | `open` → `EPERM` | `device-access-denied` |
| the storage component runs as a non-root uid | `open` → `EACCES` (the node is 0600) | `device-not-readable` |
| `CAP_SYS_ADMIN` is absent | the ioctl → `EACCES`, the kernel's own check | `privilege-missing` |
| a seccomp filter denies the syscall | the ioctl → `EPERM`, before that check runs | `syscall-blocked` |
| an LSM denies `mount(2)` | `mount` → `EACCES` | `lsm-denied` |
| `mount(2)` → `EPERM`, with the capability witnessed held | a device-mapper ioctl succeeded | `syscall-blocked` |
| `mount(2)` → `EPERM`, with no witness available | the control node is out of reach | `privilege-or-policy` |

### What crosses the boundary

Only the mount. Not the key — not by environment variable, not by a file in a
shared volume, not over an API. That property is **structural rather than tested
here**: the volume key reaches dm-crypt as a kernel keyring reference and
go-luks2 never populates the inline table field, so there is no configuration in
which the key lands somewhere an operator can read it. It is stated so a reader
knows it is reviewed, not covered by a test in this repository.

**Mount propagation is where this goes wrong in practice**, and it fails
silently: get it wrong and the workload sees an empty directory with no error and
writes to its own filesystem. Kubernetes needs `Bidirectional` propagation on the
node plugin and `HostToContainer` on the consumer; plain Docker needs a shared
bind mount. Verify it rather than assume it. A workload that only reads should
receive a read-only mount.

**An init container may attach and mount for a pod**, but the mount has to
outlive it and stay in the pod's namespace — and teardown then has no obvious
owner, so a volume left attached but unmounted leaks a plaintext device-mapper
mapping on the node. Name the owner of detach: a node plugin with a lifecycle,
not an init container that has already exited.

**Kernel keyrings are not namespaced.** Keys are scoped by uid and session on the
host, so two storage components running as the same uid can reach the same user
keyring. go-luks2 narrows this to the session ring and holds an entry only for
the duration of one activation ioctl, but the residual is real: a multi-tenant
deployment must not assume keyring isolation it does not have. Separate uids, or
separate nodes, are what separate tenants here.

## Testing

`go test ./...` runs the whole suite against fakes — no root, no LVM, no block
devices. The tests that drive real LVM, LUKS and filesystems are selected by a
build tag rather than skipped at run time, so a suite that cannot run fails
instead of quietly passing. They also require an explicit acknowledgement,
`GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1`, because they create and destroy loop
devices, volume groups and LUKS volumes on the host:

```
sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 make integration-test-local
# or, directly:
sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 go test -tags local_integration -race ./pkg/local/
```

They build their own volume group on a loopback file and tear it down again.
They need root and the `lvm2`, `e2fsprogs` and `util-linux` tooling.
`cryptsetup` is not required: the containers are formatted, unlocked and
inspected in-process by go-luks2, and the loop device is attached with the loop
ioctls rather than by forking `losetup`.
