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

//go:build linux

package preflight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"golang.org/x/sys/unix"
)

// DeviceMapperControl is the control node every device-mapper ioctl goes
// through. It is exported because an operator reading a refusal needs the exact
// path to pass into the container, and because the deployment documentation and
// the probe must not be able to drift apart.
const DeviceMapperControl = "/dev/mapper/control"

// deviceMapperSteps is the device-mapper probe broken into its three real
// operations, so a test can drive each refusal.
//
// It is a seam for the same reason go-luks2's kernelKeyring is: the failures
// that matter — a missing device node, a denied ioctl, a kernel without dm —
// cannot all be produced on one host, and the refusal paths are the entire
// point of a guard. The happy path is exercised against the real kernel
// wherever the environment provides it.
type deviceMapperSteps struct {
	open    func(path string) (int, error)
	version func(fd int) error
	close   func(fd int) error

	// openWorks reports whether this process can open(2) AT ALL. It is
	// consulted only when opening the control node answers EPERM, which two
	// different things produce.
	openWorks func() openWitness
}

// openWitness is what a positive test of open(2) concluded.
//
// Opening /dev/mapper/control can answer EPERM because the container was shown
// the node without being ALLOWED it (the device cgroup), or because a seccomp
// filter refuses the openat. The fixes are opposite — pass the device properly
// versus relax the profile — so the guard establishes which by opening a file it
// created itself, rather than asserting one.
type openWitness int

const (
	// openWitnessUnknown means the test could not be performed.
	openWitnessUnknown openWitness = iota

	// openWitnessWorks means open(2) succeeded on a file this probe created, so
	// openat is not being refused wholesale.
	openWitnessWorks

	// openWitnessBlocked means open(2) was refused on a file this probe
	// created, which only a syscall filter does.
	openWitnessBlocked
)

// mountSteps is the mount probe broken into its real operations, plus the
// witness that tells its two EPERM cases apart.
type mountSteps struct {
	tempDir func() (string, error)
	remount func(target string) error
	remove  func(path string) error

	// witness reports whether CAP_SYS_ADMIN is DEMONSTRABLY held, by performing
	// an operation the kernel gates on it. It is consulted only when mount(2)
	// answers EPERM, which is the one answer two different mechanisms produce.
	witness func() capabilityWitness
}

// capabilityWitness is what a positive test for CAP_SYS_ADMIN concluded.
//
// It exists because mount(2) returns EPERM both when the capability is absent
// and when a seccomp filter denies the syscall, and the errno does not say
// which — so a table keyed on the errno alone would send an operator to grant a
// capability they already hold, in exactly the independent-seccomp case this
// package was written to diagnose.
//
// The witness is a PROBE, not an inference: it asks the kernel to perform a
// device-mapper ioctl, which the device-mapper ioctl handler gates on
// CAP_SYS_ADMIN before it looks at anything else. A success is the kernel
// stating the capability is held. Reading CapEff instead would be the guess
// this package refuses to make everywhere else.
type capabilityWitness int

const (
	// witnessUnknown means the capability could not be demonstrated either way.
	// It is the fail-closed value: the refusal is still reported, with an
	// ambiguous cause that names both mechanisms rather than picking one.
	witnessUnknown capabilityWitness = iota

	// witnessHeld means the kernel performed an operation gated on
	// CAP_SYS_ADMIN.
	witnessHeld

	// witnessNotHeld means the kernel refused such an operation on the
	// capability check itself.
	witnessNotHeld
)

// platformProbes returns the live probes for Linux.
func platformProbes() map[Capability]Probe {
	return map[Capability]Probe{
		CapabilityDeviceMapper:  deviceMapperProbe(liveDeviceMapperSteps()),
		CapabilityMount:         mountProbe(liveMountSteps()),
		CapabilityKernelKeyring: keyringProbe(luks2.CheckKeyringAvailable),
	}
}

// liveDeviceMapperSteps talks to the real kernel.
//
// The control node is opened READ-ONLY, which is what the device-mapper library
// underneath this stack does, so the probe exercises the same access the real
// path takes rather than a stricter one that could fail where the real path
// would not.
func liveDeviceMapperSteps() deviceMapperSteps {
	return deviceMapperSteps{
		open: func(path string) (int, error) {
			return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		},
		version:   deviceMapperVersion,
		close:     unix.Close,
		openWorks: liveOpenWitness,
	}
}

// liveOpenWitness reports whether this process can open(2) a file at all.
//
// It opens a file it CREATES, in a directory it creates, and removes both — so
// it can only ever be refused by a policy, never by somebody else's
// permissions, and it leaves nothing behind. Success means openat is reaching
// the kernel, which rules a wholesale syscall filter out as the explanation for
// a refused device node; a refusal on a file this process just wrote is a filter
// and nothing else.
//
// It is deliberately NOT proof that the device node's own open would have been
// permitted: a seccomp rule can filter openat on its ARGUMENTS, so this witness
// narrows the explanation rather than settling it. The remedy it feeds names
// both fixes for that reason.
func liveOpenWitness() openWitness {
	dir, err := os.MkdirTemp("", "go-blockstore-preflight-open-")
	if err != nil {
		return openWitnessUnknown
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "witness")
	// #nosec G304 -- the path is built from a temporary directory this function
	// created a line above; nothing a caller supplies reaches it.
	if writeErr := os.WriteFile(path, []byte{0}, 0o600); writeErr != nil {
		return openWitnessUnknown
	}

	return openWitnessAt(path, func(p string) (int, error) {
		return unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}, unix.Close)
}

// openWitnessAt is liveOpenWitness's decision, with the syscalls injectable.
//
// The refusals it classifies cannot be produced on a host that can open files —
// which is every host a test runs on — so they are driven through this seam,
// the same way every other refusal in this package is.
func openWitnessAt(path string, open func(string) (int, error), closeFD func(int) error) openWitness {
	fd, openErr := open(path)
	switch {
	case openErr == nil:
		if closeErr := closeFD(fd); closeErr != nil {
			// Same stance as every other witness here: a probe that cannot
			// account for what it opened is not evidence.
			return openWitnessUnknown
		}
		return openWitnessWorks
	case errors.Is(openErr, unix.EPERM):
		return openWitnessBlocked
	default:
		return openWitnessUnknown
	}
}

// deviceMapperVersion issues DM_VERSION on an open control node.
//
// DM_VERSION is the right probe for three reasons. It is READ-ONLY — it reports
// the interface version and creates, loads and removes nothing, so there is no
// artifact to clean up and no mapping to leak. It is the FIRST thing the
// device-mapper library issues, so it is the same call the real path makes. And
// the kernel checks CAP_SYS_ADMIN at the top of the device-mapper ioctl handler,
// before it looks at which command was asked for, so a denial here is exactly
// the denial every other device-mapper operation would get.
//
// Measured 2026-09-01: inside a container with --cap-add SYS_ADMIN and
// --device /dev/mapper/control this returns interface version 4.48.0 under
// Docker's DEFAULT seccomp and AppArmor profiles — which is precisely why it
// cannot be the only check. Device-mapper working is what convinces an operator
// the container is correctly privileged while the keyring is still blocked.
func deviceMapperVersion(fd int) error {
	// A dm_ioctl header and nothing else: DM_VERSION reads and writes only the
	// fixed part of the structure.
	data := make([]byte, unix.SizeofDmIoctl)

	// #nosec G103 -- the conversion is to the kernel's own dm_ioctl layout over
	// a buffer of exactly unix.SizeofDmIoctl bytes allocated on the line above.
	// This is the only way to populate a struct the ioctl interface defines by
	// memory layout; the buffer outlives the call because data is still live.
	control := (*unix.DmIoctl)(unsafe.Pointer(&data[0]))
	control.Version = [3]uint32{4, 0, 0} // the minimum interface version required
	control.Data_size = uint32(unix.SizeofDmIoctl)
	control.Data_start = uint32(unix.SizeofDmIoctl)

	// #nosec G103 -- same buffer, passed to the kernel as the ioctl argument.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.DM_VERSION), uintptr(unsafe.Pointer(&data[0]))); errno != 0 {
		return errno
	}
	return nil
}

// liveMountSteps talks to the real kernel.
func liveMountSteps() mountSteps {
	return mountSteps{
		tempDir: func() (string, error) { return os.MkdirTemp("", "go-blockstore-preflight-") },
		remount: liveRemount,
		remove:  os.RemoveAll,
		witness: func() capabilityWitness { return deviceMapperWitness(liveDeviceMapperSteps()) },
	}
}

// deviceMapperWitness asks the kernel whether this process holds CAP_SYS_ADMIN,
// by issuing the read-only device-mapper version ioctl.
//
// Only two answers are conclusive. The ioctl SUCCEEDING proves the capability,
// because the device-mapper ioctl handler checks it before anything else. The
// ioctl answering EACCES disproves it, because EACCES is what that handler's own
// capability check returns.
//
// EPERM does NOT disprove it, and the difference is measured rather than
// reasoned about. On 2026-09-01, with /dev/mapper/control passed into a
// container running as uid 0:
//
//	no CAP_SYS_ADMIN, ioctl permitted   → EACCES (13), the kernel's own check
//	CAP_SYS_ADMIN, seccomp denies ioctl → EPERM (1), the filter, before the
//	                                      handler ever runs
//
// So reading EPERM as a missing capability would tell an operator holding
// CAP_SYS_ADMIN to grant it — the same misclassification this witness was added
// to remove, one layer down. Codex caught it on review of the first draft.
//
// Everything else is witnessUnknown, and the boundaries matter:
//
//   - The control node being ABSENT says nothing about capabilities. A
//     container can hold CAP_SYS_ADMIN and simply not have had the device
//     passed in.
//   - The control node failing to OPEN with EACCES says nothing either.
//     /dev/mapper/control is root-owned and mode 0600, so a process running as
//     a non-root uid is refused by the file permissions before the capability
//     is ever consulted — and CAP_SYS_ADMIN does not imply CAP_DAC_OVERRIDE.
//   - A probe that could not close the descriptor it opened is not evidence of
//     anything, so it does not get to be evidence of a capability either.
//
// Reading either of those as "the capability is missing" would be the same
// class of mistake as reading CapEff.
func deviceMapperWitness(steps deviceMapperSteps) capabilityWitness {
	fd, err := steps.open(DeviceMapperControl)
	if err != nil {
		return witnessUnknown
	}
	versionErr := steps.version(fd)
	closeErr := steps.close(fd)

	switch {
	case versionErr == nil && closeErr == nil:
		return witnessHeld
	case errors.Is(versionErr, unix.EACCES):
		return witnessNotHeld
	default:
		return witnessUnknown
	}
}

// liveRemount asks the kernel to remount a directory that is not a mount point,
// which is how this package establishes that mount(2) is permitted WITHOUT
// mounting anything.
//
// The ordering inside the kernel is what makes it work. path_mount consults the
// security modules, then checks the capability, and only afterwards looks at
// whether the request makes sense; do_remount's first substantive test is that
// the target is the root of a mount, and a directory this process created a
// moment ago never is. So the three answers separate cleanly:
//
//	EINVAL  the request got past every permission gate and was rejected on its
//	        merits — mount(2) is permitted
//	EPERM   the capability is missing, or a seccomp filter refused the syscall
//	EACCES  a security module denied it
//
// Nothing is ever mounted and nothing is ever remounted: the target is a fresh
// directory, so the operation cannot reach a filesystem to change. That
// structural property is the reason this probe is safe to run on a production
// host, and it is why the target must be created by this package rather than
// supplied by a caller.
func liveRemount(target string) error {
	return unix.Mount("", target, "", unix.MS_REMOUNT, "")
}

// deviceMapperProbe builds the device-mapper probe over a set of steps.
func deviceMapperProbe(steps deviceMapperSteps) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityDeviceMapper,
				Cause:      CauseIndeterminate,
				Probe:      "starting the device-mapper probe",
				Err:        err,
			}
		}

		fd, err := steps.open(DeviceMapperControl)
		if err != nil {
			return classifyDeviceMapperOpen(err, steps.openWorks)
		}

		versionErr := steps.version(fd)
		closeErr := steps.close(fd)

		if versionErr != nil {
			return classifyDeviceMapperIoctl(versionErr)
		}
		if closeErr != nil {
			// The capability itself was demonstrated, but a descriptor this
			// probe opened could not be closed. That is reported rather than
			// dropped: it means the probe did not finish cleanly, and a check
			// that cannot account for what it created is not evidence.
			return &CapabilityError{
				Capability: CapabilityDeviceMapper,
				Cause:      CauseIndeterminate,
				Probe:      "closing the descriptor the probe opened on " + DeviceMapperControl,
				Err:        closeErr,
			}
		}
		return nil
	}
}

// mountProbe builds the mount probe over a set of steps.
func mountProbe(steps mountSteps) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityMount,
				Cause:      CauseIndeterminate,
				Probe:      "starting the mount probe",
				Err:        err,
			}
		}

		target, err := steps.tempDir()
		if err != nil {
			return &CapabilityError{
				Capability: CapabilityMount,
				Cause:      CauseIndeterminate,
				Probe:      "creating the throwaway directory the mount probe addresses",
				Err:        err,
			}
		}

		remountErr := steps.remount(target)
		removeErr := steps.remove(target)

		if failure := classifyMount(remountErr, steps.witness); failure != nil {
			return failure
		}
		if removeErr != nil {
			// See deviceMapperProbe: an artifact this probe created and could
			// not remove turns a pass into an unfinished check.
			return &CapabilityError{
				Capability: CapabilityMount,
				Cause:      CauseIndeterminate,
				Probe:      "removing the throwaway directory the mount probe created at " + target,
				Err:        removeErr,
			}
		}
		return nil
	}
}

// keyringProbe builds the kernel-keyring probe over the check go-luks2 exports.
//
// The probe is DELEGATED rather than reimplemented. go-luks2 owns the kernel
// keyring in this stack: it is the package that adds the volume key, it decides
// which ring and which key type, and its CheckKeyringAvailable exercises that
// exact sequence — an add and a verified release of a throwaway 64-byte probe
// under a randomized description. A second implementation here would probe a
// slightly different thing and would drift, which is the failure mode a guard
// can least afford.
func keyringProbe(check func() error) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityKernelKeyring,
				Cause:      CauseIndeterminate,
				Probe:      "starting the kernel-keyring probe",
				Err:        err,
			}
		}
		// Assigned and tested rather than returned directly: classifyKeyring
		// returns a *CapabilityError, and returning a nil one straight into an
		// error interface produces a non-nil error holding a nil pointer, which
		// panics the first time anything renders it. Package factory guards the
		// same trap on the way out of a provider constructor.
		if failure := classifyKeyring(check()); failure != nil {
			return failure
		}
		return nil
	}
}

// deviceMapperOpenCauses maps the errno open(2) reports on the control node
// onto a cause. A map rather than a switch, per the house rule, and so that a
// reader can see the whole classification at once.
// Opening the node and issuing the ioctl fail for DIFFERENT reasons, so they get
// different causes even where they share an errno. Measured 2026-09-01 against
// /dev/mapper/control in containers:
//
//	ENOENT  the node is not in this mount namespace
//	EACCES  the node's own permissions — root-owned 0600, so a non-root uid is
//	        refused here before any capability is consulted
//	EPERM   a POLICY: the device cgroup (the node was made VISIBLE by a bind
//	        mount without being ALLOWED by --device), or a seccomp filter
//	        refusing the openat. Resolved by openWitness below rather than
//	        asserted — the two have opposite fixes.
//
// EPERM is absent from this table on purpose; classifyDeviceMapperOpen decides
// it with the witness.
var deviceMapperOpenCauses = map[unix.Errno]Cause{
	unix.ENOENT: CauseDeviceMissing,
	unix.EACCES: CauseDeviceNotReadable,
	unix.ENXIO:  CauseKernelUnsupported,
	unix.ENODEV: CauseKernelUnsupported,
}

// deviceMapperOpenEPERMCauses resolves the policy refusal with what the open
// witness concluded.
var deviceMapperOpenEPERMCauses = map[openWitness]Cause{
	openWitnessBlocked: CauseSyscallBlocked,
	openWitnessWorks:   CauseDeviceAccessDenied,
	openWitnessUnknown: CauseDeviceAccessDenied,
}

// deviceMapperOpenEPERMDetail says what the witness established, so an operator
// can see how confident the remedy is entitled to be.
var deviceMapperOpenEPERMDetail = map[openWitness]string{
	openWitnessBlocked: "; open(2) was refused on a file this process created a moment earlier, so a syscall filter is refusing openat outright",
	openWitnessWorks:   "; open(2) succeeded on a file this process created a moment earlier, so openat is not being refused wholesale",
	openWitnessUnknown: "; whether open(2) works at all could not be established here",
}

// deviceMapperIoctlCauses maps the errno the DM_VERSION ioctl reports onto a
// cause.
//
// EACCES and EPERM mean DIFFERENT things here, and conflating them is the defect
// this table was corrected for. Measured 2026-09-01: the device-mapper ioctl
// handler's own capability check answers EACCES, while a seccomp filter denying
// ioctl answers EPERM before that handler runs at all. So EPERM rules the
// capability OUT as an explanation rather than in.
//
// ENOTTY means the descriptor is not the device-mapper control node, which is
// not something this probe can interpret.
var deviceMapperIoctlCauses = map[unix.Errno]Cause{
	unix.EACCES: CausePrivilegeMissing,
	unix.EPERM:  CauseSyscallBlocked,
	unix.ENOSYS: CauseKernelUnsupported,
}

// mountCauses maps the errno the remount probe reports onto a cause.
//
// EINVAL is absent on purpose: it is the SUCCESS answer, handled in
// classifyMount. So is EPERM, which is the ambiguous one — the witness decides
// it in mountEPERMCauses rather than a table keyed on the errno alone.
var mountCauses = map[unix.Errno]Cause{
	unix.EACCES: CauseLSMDenied,
}

// mountEPERMCauses resolves the one errno two mechanisms produce, using what
// the capability witness concluded.
var mountEPERMCauses = map[capabilityWitness]Cause{
	witnessHeld:    CauseSyscallBlocked,
	witnessNotHeld: CausePrivilegeMissing,
	witnessUnknown: CausePrivilegeOrPolicy,
}

// mountEPERMProbeDetail says what the witness established, because an operator
// acting on the remedy deserves to see the evidence behind it.
var mountEPERMProbeDetail = map[capabilityWitness]string{
	witnessHeld:    ", and the kernel then confirmed CAP_SYS_ADMIN IS held by accepting a device-mapper ioctl gated on it",
	witnessNotHeld: ", and the kernel then refused a device-mapper ioctl gated on the same capability",
	witnessUnknown: ", and CAP_SYS_ADMIN could not be witnessed either way because the device-mapper control node is not reachable from here",
}

const deviceMapperOpenProbe = "opening the device-mapper control node " + DeviceMapperControl +
	" (it is root-owned and mode 0600, so this needs uid 0 or CAP_DAC_OVERRIDE as well as the node being present)"

// classifyDeviceMapperOpen turns an open(2) failure into a typed finding.
func classifyDeviceMapperOpen(err error, openWorks func() openWitness) *CapabilityError {
	// EPERM is a policy refusal, and two policies produce it with opposite
	// fixes. Which one is established by opening a file this process created,
	// not decided by whichever is more common.
	if errors.Is(err, unix.EPERM) {
		concluded := openWitnessUnknown
		if openWorks != nil {
			concluded = openWorks()
		}
		return &CapabilityError{
			Capability: CapabilityDeviceMapper,
			Cause:      deviceMapperOpenEPERMCauses[concluded],
			Probe:      deviceMapperOpenProbe + deviceMapperOpenEPERMDetail[concluded],
			Err:        err,
		}
	}

	return &CapabilityError{
		Capability: CapabilityDeviceMapper,
		Cause:      causeForErrno(err, deviceMapperOpenCauses),
		Probe:      deviceMapperOpenProbe,
		Err:        err,
	}
}

// classifyDeviceMapperIoctl turns a DM_VERSION failure into a typed finding.
func classifyDeviceMapperIoctl(err error) *CapabilityError {
	return &CapabilityError{
		Capability: CapabilityDeviceMapper,
		Cause:      causeForErrno(err, deviceMapperIoctlCauses),
		Probe:      "issuing the read-only DM_VERSION ioctl on " + DeviceMapperControl,
		Err:        err,
	}
}

// classifyMount turns the remount probe's answer into a typed finding, or nil
// when mount(2) is permitted.
//
// EINVAL is the pass: the kernel got past the security modules and the
// capability check and rejected the request because the target is not a mount
// root. A nil error is also treated as a pass — it cannot occur, because the
// target is a directory this package created and a fresh directory is never the
// root of a mount, but reading an outright success as a failure would be a
// guard refusing an environment that demonstrably works.
func classifyMount(err error, witness func() capabilityWitness) *CapabilityError {
	if err == nil || errors.Is(err, unix.EINVAL) {
		return nil
	}

	const probe = "asking the kernel to remount a directory that is not a mount point, which reaches the permission checks without mounting anything"

	// EPERM is the answer BOTH a missing CAP_SYS_ADMIN and a seccomp denial
	// produce, so it is resolved by asking the kernel to demonstrate the
	// capability rather than by assuming which one it was.
	if errors.Is(err, unix.EPERM) {
		concluded := witnessUnknown
		if witness != nil {
			concluded = witness()
		}
		return &CapabilityError{
			Capability: CapabilityMount,
			Cause:      mountEPERMCauses[concluded],
			Probe:      probe + mountEPERMProbeDetail[concluded],
			Err:        err,
		}
	}

	return &CapabilityError{
		Capability: CapabilityMount,
		Cause:      causeForErrno(err, mountCauses),
		Probe:      probe,
		Err:        err,
	}
}

// keyringCauses maps go-luks2's keyring sentinels onto this package's causes.
//
// It is an ordered slice rather than a map because the sentinels are matched
// with errors.Is and the order decides which of two matching entries wins; map
// iteration order would make the classification of an error that matches more
// than one sentinel vary between runs.
var keyringCauses = []struct {
	sentinel error
	cause    Cause
}{
	{luks2.ErrKeyringBlocked, CauseSyscallBlocked},
	{luks2.ErrKeyringUnsupported, CauseKernelUnsupported},
	{luks2.ErrKeyringQuotaExhausted, CauseResourceExhausted},
}

// classifyKeyring turns go-luks2's answer into a typed finding, or nil when the
// keyring is usable.
//
// Anything go-luks2 reports that does not match one of the classified sentinels
// is CauseIndeterminate rather than a generic failure: an unrecognized keyring
// condition is exactly the case where guessing would be wrong, and the
// underlying error carries go-luks2's own explanation.
func classifyKeyring(err error) *CapabilityError {
	if err == nil {
		return nil
	}
	cause := CauseIndeterminate
	for _, entry := range keyringCauses {
		if errors.Is(err, entry.sentinel) {
			cause = entry.cause
			break
		}
	}
	return &CapabilityError{
		Capability: CapabilityKernelKeyring,
		Cause:      cause,
		Probe:      "adding a throwaway key to the kernel keyring and confirming its release, the sequence an encrypted volume's activation performs",
		Err:        err,
	}
}

// causeForErrno looks an errno up in a classification table.
//
// An error that is not an errno at all, or an errno with no row, is
// CauseIndeterminate — the fail-closed direction. It is deliberately NOT
// "probably a permission problem": a guard that guesses a cause hands the
// operator a remedy for a condition it did not diagnose, and a wrong remedy
// wastes the outage rather than ending it.
func causeForErrno(err error, table map[unix.Errno]Cause) Cause {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return CauseIndeterminate
	}
	if cause, ok := table[errno]; ok {
		return cause
	}
	return CauseIndeterminate
}
