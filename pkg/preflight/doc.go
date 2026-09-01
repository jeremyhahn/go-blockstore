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

// Package preflight refuses to start a storage component whose deployment
// cannot do the privileged work it is about to be asked for.
//
// It exists because the alternative is a paragraph in a README explaining that
// volume attach will fail, which is a thing to code rather than a thing to
// document. Every check here ATTEMPTS the operation and reports a typed,
// actionable refusal naming the exact remedy.
//
// # The deployment being guarded
//
// Attaching an encrypted volume needs privilege. That privilege belongs in
// exactly ONE small, audited component — a control plane, an init container, a
// CSI node plugin — and never in the workload:
//
//	┌─────────────────────────────┐        ┌──────────────────────────┐
//	│ storage component           │        │ workload container       │
//	│ (control-plane / init /     │        │                          │
//	│  CSI node plugin)           │        │  NO capabilities         │
//	│                             │        │  NO seccomp exception    │
//	│  CAP_SYS_ADMIN              │───────▶│  NO device access        │
//	│  seccomp: default + 3       │ mount  │  NEVER sees the key      │
//	│  /dev/mapper/control        │        │                          │
//	│  the block device           │        │  just a mounted fs       │
//	└─────────────────────────────┘        └──────────────────────────┘
//
// The storage component unseals the key, attaches the LUKS volume, mounts the
// filesystem, and hands the ALREADY-MOUNTED filesystem to the workload.
//
// # The workload's requirements: none
//
// This is the whole point and the thing an operator most needs to know. The
// workload container needs no capabilities, no seccomp exception, no device
// access and no key. It receives a directory. If a deployment finds itself
// granting the workload CAP_SYS_ADMIN, it has the shape wrong.
//
// # The storage component's minimum
//
// Measured, not assumed:
//
//   - CAP_SYS_ADMIN — device-mapper ioctls and mount(2).
//   - seccomp: the runtime default PLUS add_key, keyctl and request_key.
//   - an LSM profile that permits mount(2).
//   - /dev/mapper/control, passed in as a device.
//   - the specific block device, and nothing else under /dev.
//
// NEVER --privileged. It grants every capability, disables the seccomp profile
// and the LSM confinement wholesale, and exposes every host device — so it
// replaces a bounded grant with an unbounded one, and it is not the fix for any
// failure this package reports.
//
// # The three mechanisms are independent, and that is the trap
//
// Capabilities, seccomp and LSM confinement are enforced by different
// subsystems. Granting one does not lift another, and all three surface as a
// bare "operation not permitted". Measured on 2026-09-01, in a container with
// --cap-add SYS_ADMIN and --device /dev/mapper/control under Docker's DEFAULT
// profiles:
//
//	device-mapper   works — DM_VERSION returns interface version 4.48.0
//	kernel keyring  BLOCKED — seccomp denies add_key/keyctl/request_key
//	mount(2)        BLOCKED — the default AppArmor profile denies it
//
// So an operator grants CAP_SYS_ADMIN, watches device-mapper work, and concludes
// the container is correctly privileged. The keyring failure then arrives later,
// under load, in a code path that looks like a storage fault rather than a
// container-configuration fault. That is the specific outage this package moves
// to startup, which is why each mechanism is probed SEPARATELY and each refusal
// names which one is missing.
//
// # Probe, do not infer
//
// Nothing here reads CapEff and reasons about it. A capability bit says a
// capability was granted; it says nothing about whether a seccomp filter or a
// security module will allow the syscall that uses it — and in the case above,
// reading CapEff would have reported full confidence in a container that cannot
// unlock a volume. Every check performs the operation.
//
// # One errno, two mechanisms
//
// mount(2) answers EPERM both when CAP_SYS_ADMIN is absent and when a seccomp
// filter denies the syscall. Naming one of them confidently would send an
// operator to grant a capability they already hold — the exact wrong turn in the
// case above. So EPERM is resolved by asking the kernel to DEMONSTRATE the
// capability: a device-mapper ioctl, which the kernel gates on CAP_SYS_ADMIN
// before it looks at anything else. It succeeding proves the capability, so the
// mount denial is seccomp; it being refused disproves it. Where that witness is
// out of reach — no control node, or a node this uid cannot open — the
// ambiguity is REPORTED (CausePrivilegeOrPolicy) and the remedy names both
// mechanisms, rather than being guessed.
//
// # Fail closed
//
// A probe that cannot establish an answer reports CauseIndeterminate and the
// check FAILS. A guard that defaults to "probably fine" when its own check
// errors is worse than no guard: it converts an unknown into a green light. The
// same applies to an empty capability list (ErrNoCapabilities) and to a
// capability with no registered probe (UnknownCapabilityError) — a caller that
// silently checked nothing must not be told everything is fine.
//
// # Probes clean up after themselves
//
// The device-mapper probe is read-only: DM_VERSION creates, loads and removes
// nothing. The mount probe addresses a directory it creates and removes, and
// asks for a remount of something that is not a mount point, so it reaches the
// permission checks without mounting anything. The keyring probe is go-luks2's
// own, which adds a randomly-named throwaway key and VERIFIES its removal. A
// probe whose cleanup fails turns a pass into an indeterminate failure rather
// than reporting success over an artifact it left behind.
//
// # Where the checks belong
//
//	preflight.Check(ctx, preflight.CapabilityDeviceMapper,
//	                     preflight.CapabilityMount,
//	                     preflight.CapabilityKernelKeyring)
//
// Call it during initialization, before serving anything. Package local calls
// it from New for the capabilities its configuration implies, so a provider
// constructed in a misconfigured container refuses to be built at all.
//
// # What crosses the boundary, and what does not
//
// Only the mount crosses. The key does not: not as an environment variable, not
// as a file in a shared volume, not over an API. A shared volume is exactly
// where somebody would be tempted to drop a key file, so it is worth stating
// that the workload has no use for one — it is handed a filesystem that is
// already decrypted.
//
// That property is STRUCTURAL rather than tested here. The volume key reaches
// dm-crypt as a kernel keyring REFERENCE rather than inline in the
// device-mapper table, and go-luks2 never populates the inline field, so there
// is no configuration in which the key reaches the table an operator can read.
// This package does not assert it; it is stated so that a reader knows it is a
// reviewed property and not one this code covers.
//
// # Mount propagation, the silent failure
//
// The mount must be visible in the workload's namespace, and getting this wrong
// produces an EMPTY DIRECTORY WITH NO ERROR — the workload starts, sees
// nothing, and writes to the container's own filesystem. In Kubernetes that is
// Bidirectional propagation on the node plugin and HostToContainer on the
// consumer; in plain Docker it is a shared bind mount. Verify it rather than
// assume it: after the storage component reports the volume mounted, the
// workload should see a non-empty directory whose device number differs from
// its parent's. A workload that only reads should receive a read-only mount.
//
// # The init-container variant, and who tears down
//
// An init container may attach and mount for a pod, but the mount has to
// outlive it and stay in the pod's namespace. The trap is the other end:
// teardown has no obvious owner in that shape, and a volume left attached but
// unmounted leaks a plaintext device-mapper mapping on the node. Name the owner
// of detach — a node plugin with a lifecycle, not the init container that has
// already exited.
//
// # Multi-tenancy: kernel keyrings are not namespaced
//
// Keys are scoped by uid and by session on the HOST, not by container. Two
// storage components running as the same uid can reach the same user keyring.
// go-luks2 narrows this by resolving the session keyring and holding an entry
// only for the duration of one activation ioctl, but the residual is real: a
// multi-tenant deployment must not assume keyring isolation it does not have.
// Separate uids, or separate nodes, are what actually separate tenants here.
package preflight
