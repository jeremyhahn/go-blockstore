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

package preflight

import (
	"errors"
	"strings"
)

// Cause classifies WHY a capability is unavailable, because the remedies are
// different and an operator handed "permission denied" cannot tell them apart.
//
// The distinction that matters most in a container is between a missing
// PRIVILEGE and a blocked SYSCALL. They are independent mechanisms enforced by
// different subsystems, they both surface as EPERM, and granting the first does
// not lift the second — which is the trap this package exists to catch. See the
// package documentation.
type Cause string

const (
	// CausePrivilegeMissing means the process lacks the capability the
	// operation requires — CAP_SYS_ADMIN, in everything this package probes.
	CausePrivilegeMissing Cause = "privilege-missing"

	// CauseSyscallBlocked means the syscall itself is refused by a seccomp
	// filter, whatever capabilities the process holds.
	CauseSyscallBlocked Cause = "syscall-blocked"

	// CausePrivilegeOrPolicy means the operation was refused with EPERM and the
	// two mechanisms that produce it could not be told apart.
	//
	// mount(2) answers EPERM both when CAP_SYS_ADMIN is absent and when a
	// seccomp filter denies the syscall, and the errno is identical. This
	// package resolves it where it can, by asking the kernel to demonstrate the
	// capability through a device-mapper ioctl — see the mount probe. Where that
	// witness is unavailable, the ambiguity is REPORTED rather than resolved by
	// guessing: naming one mechanism confidently would send an operator to fix
	// the wrong one, which costs the outage rather than ending it.
	CausePrivilegeOrPolicy Cause = "privilege-or-policy"

	// CauseLSMDenied means a Linux Security Module — AppArmor or SELinux —
	// denied the operation. It is a THIRD independent mechanism: measured on
	// 2026-09-01, Docker's default AppArmor profile denies mount(2) even for a
	// container granted CAP_SYS_ADMIN with the syscall permitted by seccomp.
	CauseLSMDenied Cause = "lsm-denied"

	// CauseDeviceMissing means the device node the operation needs is not
	// present — most often a container that was granted the capability but
	// never had the device passed in.
	CauseDeviceMissing Cause = "device-missing"

	// CauseDeviceAccessDenied means the device node is PRESENT and the kernel
	// refused to open it with EPERM — the container was allowed to see the node
	// without being allowed to use it.
	//
	// Measured 2026-09-01: bind-mounting /dev/mapper/control into a container
	// without a device-cgroup allowance produces exactly this, and no capability
	// grant changes it. It is a different fix from every other refusal here, and
	// it is the one a hostPath in Kubernetes walks straight into.
	CauseDeviceAccessDenied Cause = "device-access-denied"

	// CauseDeviceNotReadable means the device node is present, reachable, and
	// refused by its own permissions (EACCES) rather than by any policy.
	//
	// /dev/mapper/control is root-owned and mode 0600, so a storage component
	// running as a non-root uid is refused here before the kernel ever consults
	// a capability — and CAP_SYS_ADMIN does not imply CAP_DAC_OVERRIDE, so
	// granting it fixes nothing.
	CauseDeviceNotReadable Cause = "device-not-readable"

	// CauseKernelUnsupported means the kernel cannot do this at all: the module
	// is absent, or it was built without the feature. No runtime configuration
	// changes it.
	CauseKernelUnsupported Cause = "kernel-unsupported"

	// CauseResourceExhausted means the facility is reachable and a limit is
	// full — the per-user kernel key quota, for instance.
	CauseResourceExhausted Cause = "resource-exhausted"

	// CausePlatformUnsupported means the probe cannot run on this GOOS.
	CausePlatformUnsupported Cause = "platform-unsupported"

	// CauseIndeterminate means the probe could not establish an answer.
	//
	// It is a FAILURE, not a shrug. A guard that reports success when its own
	// check broke is worse than no guard, because it converts an unknown into a
	// green light; every path in this package that cannot decide ends here and
	// refuses.
	CauseIndeterminate Cause = "indeterminate"

	// CauseMountNotPropagated means a mount succeeded and is not visible
	// outside the namespace that made it.
	//
	// It is its own cause because nothing else in this package describes a
	// SUCCESSFUL operation whose result does not reach the consumer, and
	// because its remedy is unlike every other one here: no capability, no
	// seccomp rule and no LSM profile changes it. The propagation of the parent
	// mount does, and that is set on the node and in the container's own mount
	// configuration.
	CauseMountNotPropagated Cause = "mount-not-propagated"
)

// The sentinels callers match with errors.Is. ErrUnavailable is the root and
// matches every CapabilityError; the rest match exactly one Cause, because each
// needs a different fix.
var (
	// ErrUnavailable is the root: every failure this package reports matches
	// it. Use it for the catch-all branch.
	ErrUnavailable = errors.New("go-blockstore/preflight: a required capability is unavailable")

	// ErrPrivilegeMissing matches CausePrivilegeMissing.
	ErrPrivilegeMissing = errors.New("go-blockstore/preflight: the process lacks a required capability")

	// ErrSyscallBlocked matches CauseSyscallBlocked.
	ErrSyscallBlocked = errors.New("go-blockstore/preflight: a required syscall is blocked by policy")

	// ErrPrivilegeOrPolicy matches CausePrivilegeOrPolicy — EPERM, with the
	// capability and the seccomp filter indistinguishable.
	ErrPrivilegeOrPolicy = errors.New("go-blockstore/preflight: the operation was refused, and the capability and the syscall filter cannot be told apart")

	// ErrLSMDenied matches CauseLSMDenied.
	ErrLSMDenied = errors.New("go-blockstore/preflight: a security module denied the operation")

	// ErrDeviceMissing matches CauseDeviceMissing.
	ErrDeviceMissing = errors.New("go-blockstore/preflight: a required device node is not present")

	// ErrDeviceAccessDenied matches CauseDeviceAccessDenied.
	ErrDeviceAccessDenied = errors.New("go-blockstore/preflight: a required device node is present but this container may not use it")

	// ErrDeviceNotReadable matches CauseDeviceNotReadable.
	ErrDeviceNotReadable = errors.New("go-blockstore/preflight: a required device node is refused by its own permissions")

	// ErrKernelUnsupported matches CauseKernelUnsupported.
	ErrKernelUnsupported = errors.New("go-blockstore/preflight: this kernel does not provide a required facility")

	// ErrResourceExhausted matches CauseResourceExhausted.
	ErrResourceExhausted = errors.New("go-blockstore/preflight: a kernel resource limit is exhausted")

	// ErrPlatformUnsupported matches CausePlatformUnsupported.
	ErrPlatformUnsupported = errors.New("go-blockstore/preflight: this platform cannot provide a required capability")

	// ErrMountNotPropagated matches CauseMountNotPropagated.
	ErrMountNotPropagated = errors.New("go-blockstore/preflight: a mount is not visible outside the namespace that made it")

	// ErrIndeterminate matches CauseIndeterminate — the probe could not
	// establish an answer, which this package treats as a failure.
	ErrIndeterminate = errors.New("go-blockstore/preflight: a probe could not determine whether a capability is available")
)

// causeSentinels maps a Cause onto the sentinel that matches it. It is the
// dispatch table CapabilityError.Is consults; a Cause absent from it matches
// nothing but ErrUnavailable, which is the fail-closed direction.
var causeSentinels = map[Cause]error{
	CausePrivilegeMissing:    ErrPrivilegeMissing,
	CauseSyscallBlocked:      ErrSyscallBlocked,
	CausePrivilegeOrPolicy:   ErrPrivilegeOrPolicy,
	CauseLSMDenied:           ErrLSMDenied,
	CauseDeviceMissing:       ErrDeviceMissing,
	CauseDeviceAccessDenied:  ErrDeviceAccessDenied,
	CauseDeviceNotReadable:   ErrDeviceNotReadable,
	CauseKernelUnsupported:   ErrKernelUnsupported,
	CauseResourceExhausted:   ErrResourceExhausted,
	CausePlatformUnsupported: ErrPlatformUnsupported,
	CauseIndeterminate:       ErrIndeterminate,
	CauseMountNotPropagated:  ErrMountNotPropagated,
}

// CapabilityError reports that one capability this deployment needs is not
// available, and says what to do about it.
//
// It carries the four things an operator staring at a crashed container has to
// have: WHICH capability, WHAT was attempted, WHY it failed classified into a
// cause with its own fix, and the kernel's own answer underneath. Error()
// renders all four plus the remedy, because this message is very often the only
// artifact anybody sees.
type CapabilityError struct {
	// Capability is the capability that is unavailable.
	Capability Capability

	// Cause classifies the failure. See Cause.
	Cause Cause

	// Probe describes what was actually attempted, in words — "opening
	// /dev/mapper/control", not a function name. The probe is the evidence, so
	// it is reported rather than left implicit.
	Probe string

	// Err is the underlying error, normally a syscall errno. It may be nil when
	// the refusal is structural (an unsupported platform).
	Err error
}

// Error renders the whole finding: capability, probe, cause, kernel answer and
// remedy.
func (e *CapabilityError) Error() string {
	var b strings.Builder
	b.WriteString("go-blockstore/preflight: ")
	b.WriteString(string(e.Capability))
	b.WriteString(" is unavailable: ")
	b.WriteString(e.Probe)
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	b.WriteString(" [")
	b.WriteString(string(e.Cause))
	b.WriteString("]. ")
	b.WriteString(e.Remedy())
	return b.String()
}

// Unwrap exposes the kernel's own error so a caller can match an errno.
func (e *CapabilityError) Unwrap() error { return e.Err }

// Is matches ErrUnavailable for every failure and the one sentinel that
// corresponds to this failure's Cause.
//
// It does NOT fall through to the wrapped error — Unwrap already does that, and
// errors.Is walks the chain itself.
func (e *CapabilityError) Is(target error) bool {
	if target == ErrUnavailable {
		return true
	}
	sentinel, ok := causeSentinels[e.Cause]
	return ok && target == sentinel
}

// Remedy returns the specific fix for this capability and cause.
//
// It is looked up per (capability, cause) first and falls back to a per-cause
// answer, so a new capability inherits something useful rather than nothing.
// NOTHING here ever suggests --privileged: that grants every capability, drops
// the seccomp profile AND the LSM confinement, and exposes every host device,
// which is the opposite of the deployment this package is guarding.
func (e *CapabilityError) Remedy() string {
	if specific, ok := remedies[remedyKey{e.Capability, e.Cause}]; ok {
		return specific
	}
	if general, ok := causeRemedies[e.Cause]; ok {
		return general
	}
	return "This is not a condition this package knows a fix for; the error above is the kernel's own answer."
}

// remedyKey identifies the most specific remedy: the pair of capability and
// cause. A map rather than nested switches, so adding a capability is adding
// rows.
type remedyKey struct {
	capability Capability
	cause      Cause
}

const neverPrivileged = "Do NOT use --privileged as a fix: it grants every capability, disables the seccomp profile and the LSM confinement wholesale, and exposes every host device."

// remedies is the (capability, cause) → fix table. Every entry names the
// concrete flag or field to change.
var remedies = map[remedyKey]string{
	{CapabilityDeviceMapper, CausePrivilegeMissing}: "The control node opened and the kernel then refused the device-mapper ioctl on its own capability check, which is CAP_SYS_ADMIN. Grant it to the STORAGE component only — docker: --cap-add SYS_ADMIN; Kubernetes: securityContext.capabilities.add: [\"SYS_ADMIN\"]. The workload container that receives the mounted filesystem needs none of this. " + neverPrivileged,

	{CapabilityDeviceMapper, CauseDeviceAccessDenied}: "The control node is present and a POLICY refused the open, which is one of two things and the finding above says how far this check could narrow it. Most likely the device cgroup: the node was made VISIBLE without being ALLOWED — measured 2026-09-01, bind-mounting /dev/mapper/control produces exactly this. Pass the device properly — docker: --device /dev/mapper/control, NOT -v /dev/mapper/control:/dev/mapper/control; Kubernetes: the node must be allowed to the container, not merely mounted into it. IF THE DEVICE IS ALREADY PASSED THAT WAY, the remaining explanation is a seccomp rule filtering openat by its arguments, or an LSM denying the open — check the profile rather than widening device access further. No capability grant fixes either. " + neverPrivileged,

	{CapabilityDeviceMapper, CauseDeviceNotReadable}: "The control node is present and reachable, and its own permissions refused the open: it is root-owned and mode 0600. Run the storage component as uid 0, or grant CAP_DAC_OVERRIDE. CAP_SYS_ADMIN does NOT imply CAP_DAC_OVERRIDE, so granting it will not help; a security module denying open would look the same, so check the LSM profile if the uid is already 0. " + neverPrivileged,

	{CapabilityDeviceMapper, CauseSyscallBlocked}: "A policy is refusing the syscall this check needs, and CAP_SYS_ADMIN is NOT the explanation — measured: the device-mapper ioctl handler's own capability check answers EACCES, while a seccomp filter denying the syscall answers EPERM, which is what happened here. Granting more capabilities will change nothing. Allow the syscall (openat, or ioctl) in the seccomp profile the storage component runs under, in a NARROW custom profile; check the LSM profile too if seccomp already permits it. " + neverPrivileged,

	{CapabilityDeviceMapper, CauseDeviceMissing}: "The device-mapper control node is not present in this mount namespace. Pass it in — docker: --device /dev/mapper/control; Kubernetes: a hostPath volume for /dev/mapper/control on the node plugin. A capability does not create the node, so --cap-add SYS_ADMIN alone will not fix this.",

	{CapabilityDeviceMapper, CauseKernelUnsupported}: "The kernel has no device-mapper. Load dm-mod on the NODE (modprobe dm-mod) — a container cannot load it for itself — or run on a kernel built with CONFIG_BLK_DEV_DM.",

	{CapabilityKernelKeyring, CauseSyscallBlocked}: "The kernel keyring syscalls are refused by policy. This is the failure that hides behind a working device-mapper: capabilities and seccomp are independent, and CAP_SYS_ADMIN does NOT lift a seccomp denial (measured). The underlying error names the syscalls and the profile change. It belongs to the STORAGE component only — the workload container never holds a key and needs no keyring access.",

	{CapabilityKernelKeyring, CauseKernelUnsupported}: "This kernel was built without CONFIG_KEYS, so it cannot hold a volume key at all and no runtime configuration will change that. Encrypted volumes require a kernel with keyring support; there is no fallback that puts the key in the device-mapper table, by design.",

	{CapabilityKernelKeyring, CauseResourceExhausted}: "The per-user kernel key quota is full. Raise /proc/sys/kernel/keys/maxkeys and maxbytes (root_maxkeys and root_maxbytes for uid 0) on the NODE, or find what is leaking keys with `keyctl show` — this stack releases every entry it creates as soon as the activation ioctl returns.",

	{CapabilityMount, CausePrivilegeMissing}: "mount(2) requires CAP_SYS_ADMIN, and the kernel confirmed this process does not hold it — a device-mapper ioctl, which is gated on the same capability, was denied as well. Grant it to the STORAGE component only — docker: --cap-add SYS_ADMIN; Kubernetes: securityContext.capabilities.add: [\"SYS_ADMIN\"]. " + neverPrivileged,

	{CapabilityMount, CauseSyscallBlocked}: "A seccomp filter is denying mount(2). CAP_SYS_ADMIN is NOT the problem — the kernel demonstrated this process holds it by accepting a device-mapper ioctl gated on the same capability — so granting more capabilities will change nothing. Allow mount(2) in the seccomp profile the storage component runs under; a runtime's default profile permits it once CAP_SYS_ADMIN is granted, so a profile that still denies it is a custom one. " + neverPrivileged,

	{CapabilityMount, CausePrivilegeOrPolicy}: "mount(2) was refused with EPERM, which means EITHER that CAP_SYS_ADMIN is absent OR that a seccomp filter denies the syscall — the kernel returns the same errno for both, and the capability could not be demonstrated here because the device-mapper control node used to witness it is not reachable. CHECK BOTH: grant CAP_SYS_ADMIN to the storage component (docker: --cap-add SYS_ADMIN) and confirm the seccomp profile permits mount. " + neverPrivileged,

	{CapabilityMountPropagation, CauseMountNotPropagated}: mountPropagationRemedy,

	{CapabilityMountPropagation, CauseIndeterminate}: "The propagation of the mount could not be established, which is reported as a failure rather than assumed to be fine: " +
		"this check reads /proc/self/mountinfo, and a container that does not have /proc mounted, or has it mounted with hidepid restrictions, cannot answer the question at all. " +
		"Mount /proc in the storage component. A guard that passed here would be reporting a handoff it never verified, which is the failure it exists to prevent.",

	{CapabilityMount, CauseLSMDenied}: "A security module is denying mount(2) — measured 2026-09-01: Docker's DEFAULT AppArmor profile denies it even with CAP_SYS_ADMIN granted and the syscall permitted by seccomp, so this is a third mechanism that must be relaxed independently. Give the storage component a profile that permits mount — docker: --security-opt apparmor=<profile>; Kubernetes: an annotation or a node-level profile. " + neverPrivileged,
}

var mountPropagationRemedy = "The mount succeeded and is PRIVATE, so it exists only in this mount namespace: " +
	"a workload elsewhere walks to that path and finds the directory as it was before anything was mounted on it, " +
	"with no error at any layer. No capability, seccomp rule or LSM profile changes this. " +
	"A mount inherits its parent's propagation, so the fix is upstream of the mount: " +
	"Kubernetes — set mountPropagation: Bidirectional on the volumeMount in the STORAGE component (it requires privileged: true on that container) " +
	"and mountPropagation: HostToContainer on the workload that consumes it. " +
	"Docker — the host directory must itself be a shared mount (mount --make-rshared <dir> on the node, once) " +
	"and the bind must carry the propagation: --mount type=bind,source=<dir>,target=<dir>,bind-propagation=rshared. " +
	"Note that -v <dir>:<dir> WITHOUT :rshared produces exactly this finding. " +
	"Verify with: findmnt -o TARGET,PROPAGATION <dir>, or the shared: field in /proc/self/mountinfo. " + neverPrivileged

// causeRemedies is the per-cause fallback, used when no (capability, cause) row
// is more specific.
var causeRemedies = map[Cause]string{
	CausePrivilegeMissing:    "The process lacks the capability this operation requires. Grant it to the storage component only. " + neverPrivileged,
	CausePrivilegeOrPolicy:   "The operation was refused with an errno that a missing capability and a syscall filter both produce, and the two could not be told apart here. Check both rather than assuming one. " + neverPrivileged,
	CauseSyscallBlocked:      "A seccomp filter is refusing this syscall. Allow it in a NARROW custom profile rather than running unconfined, and note that granting a capability does not lift a seccomp denial. " + neverPrivileged,
	CauseLSMDenied:           "A security module (AppArmor or SELinux) denied the operation. Adjust the profile the storage component runs under. " + neverPrivileged,
	CauseDeviceMissing:       "A device node this operation needs is not present in this mount namespace. Pass the specific device in; do not widen access to every device.",
	CauseDeviceAccessDenied:  "The device node is present and this container may not use it. Allow the specific device rather than merely making it visible; do not widen access to every device.",
	CauseDeviceNotReadable:   "The device node's own permissions refused the open. Run as a uid that may open it, or grant CAP_DAC_OVERRIDE — which CAP_SYS_ADMIN does not imply.",
	CauseKernelUnsupported:   "The kernel does not provide this facility. It is fixed on the node, not in the container configuration.",
	CauseResourceExhausted:   "A kernel resource limit is full. Raise the limit on the node or find what is consuming it.",
	CausePlatformUnsupported: "This capability exists only on Linux. Run the storage component on Linux; the workload that consumes the mounted filesystem is unaffected.",
	CauseMountNotPropagated:  mountPropagationRemedy,
	CauseIndeterminate:       "The probe could not establish an answer, which is reported as a failure rather than assumed to be fine. Read the underlying error: the check itself broke, and a preflight that guessed here would be worse than none.",
}

// UnknownCapabilityError reports a capability name no probe is registered for.
//
// It is an error rather than something skipped for the same reason the
// provider rejects an unrecognized settings key: a caller that asked for a
// capability by a name nothing answers to believes it checked something, and
// silently checking nothing is the exact failure mode this package exists to
// remove.
type UnknownCapabilityError struct {
	Capability Capability
	Known      []Capability
}

// Is makes an unregistered capability reach the documented catch-all, for the
// same reason ErrNoCapabilities does: it is a fail-closed refusal, and a caller
// whose only branch is errors.Is(err, ErrUnavailable) must not miss it.
func (e *UnknownCapabilityError) Is(target error) bool { return target == ErrUnavailable }

// Error names the unknown capability and what is available.
func (e *UnknownCapabilityError) Error() string {
	known := make([]string, 0, len(e.Known))
	for _, c := range e.Known {
		known = append(known, string(c))
	}
	return "go-blockstore/preflight: no probe is registered for capability " +
		string(e.Capability) + "; known capabilities are " + strings.Join(known, ", ")
}

// ErrNoCapabilities is returned by Check when it is asked to verify nothing.
//
// An empty request returns success under every reasonable reading, and a caller
// whose capability list came out empty by accident would take that as proof its
// deployment is fine. Refusing is the fail-closed answer.
//
// It matches ErrUnavailable, because a caller that built its capability list
// dynamically and got an empty one is exactly the caller whose only branch is
// the catch-all — and a fail-closed condition that slips past the catch-all is
// a fail-closed condition nobody handles.
var ErrNoCapabilities error = noCapabilitiesError{}

// noCapabilitiesError exists only so ErrNoCapabilities can match ErrUnavailable
// as well as itself.
type noCapabilitiesError struct{}

func (noCapabilitiesError) Error() string {
	return "go-blockstore/preflight: no capabilities were requested; a preflight over nothing is not a pass"
}

// Is makes the root sentinel match. Identity still works: errors.Is compares
// the values first, and ErrNoCapabilities is the only value of this type.
func (noCapabilitiesError) Is(target error) bool { return target == ErrUnavailable }
