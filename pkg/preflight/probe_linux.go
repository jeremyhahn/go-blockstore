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
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"golang.org/x/sys/unix"
)

// DeviceMapperControl is the control node every device-mapper ioctl goes through.
const DeviceMapperControl = "/dev/mapper/control"

// deviceMapperSteps is the device-mapper probe split into its three operations, so tests can drive each refusal.
type deviceMapperSteps struct {
	open    func(path string) (int, error)
	version func(fd int) error
	close   func(fd int) error

	// openWorks reports whether this process can open(2) AT ALL. It is
	// consulted only when opening the control node answers EPERM, which two
	// different things produce.
	openWorks func() openWitness
}

// openWitness is what opening a self-created file concluded, to tell a device-cgroup EPERM from a seccomp one.
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

	// witness reports whether CAP_SYS_ADMIN is demonstrably held; consulted only when mount(2) answers EPERM.
	witness func() capabilityWitness
}

// capabilityWitness is what a device-mapper ioctl, gated on CAP_SYS_ADMIN, concluded about the capability.
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
		CapabilityKernelKeyring: keyringProbe(dmcrypt.CheckKeyring),
		CapabilityNetAdmin:      netAdminProbe(liveNetAdminSteps()),
		CapabilityDRBDControl:   drbdControlProbe(liveDRBDControlSteps()),
	}
}

// liveDeviceMapperSteps talks to the real kernel, opening the control node read-only as the real path does.
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

// liveOpenWitness reports whether this process can open(2) a file it creates and removes; it narrows, not settles, a device-node EPERM.
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

// openWitnessAt is liveOpenWitness's decision with the syscalls injectable.
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

// deviceMapperVersion issues the read-only DM_VERSION ioctl on an open control node.
func deviceMapperVersion(fd int) error {
	// A dm_ioctl header and nothing else: DM_VERSION reads and writes only the
	// fixed part of the structure.
	data := make([]byte, unix.SizeofDmIoctl)

	// #nosec G103 -- populates the kernel's dm_ioctl layout over a buffer of exactly unix.SizeofDmIoctl bytes that outlives the call.
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

// deviceMapperWitness reports whether this process holds CAP_SYS_ADMIN: DM_VERSION succeeding proves it, EACCES disproves it, anything else is witnessUnknown.
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

// liveRemount remounts a fresh non-mount-point directory: EINVAL means mount(2) is permitted, EPERM capability or seccomp, EACCES an LSM. Nothing is mounted.
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
			// A descriptor could not be closed; the probe did not finish cleanly.
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

// keyringProbe builds the kernel-keyring probe over go-luks2's dmcrypt.CheckKeyring.
func keyringProbe(check func(context.Context) error) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityKernelKeyring,
				Cause:      CauseIndeterminate,
				Probe:      "starting the kernel-keyring probe",
				Err:        err,
			}
		}
		// Tested rather than returned directly, to avoid a typed-nil error.
		if failure := classifyKeyring(check(ctx)); failure != nil {
			return failure
		}
		return nil
	}
}

// deviceMapperOpenCauses maps open(2)'s errno on the control node to a cause; EPERM is decided by classifyDeviceMapperOpen with the witness.
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

// deviceMapperIoctlCauses maps DM_VERSION's errno to a cause: EACCES is the capability check, EPERM a seccomp filter.
var deviceMapperIoctlCauses = map[unix.Errno]Cause{
	unix.EACCES: CausePrivilegeMissing,
	unix.EPERM:  CauseSyscallBlocked,
	unix.ENOSYS: CauseKernelUnsupported,
}

// mountCauses maps the remount probe's errno to a cause; EINVAL (pass) and EPERM (witness) are handled elsewhere.
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

// classifyMount turns the remount probe's answer into a finding, or nil when mount(2) is permitted (EINVAL or nil).
func classifyMount(err error, witness func() capabilityWitness) *CapabilityError {
	if err == nil || errors.Is(err, unix.EINVAL) {
		return nil
	}

	const probe = "asking the kernel to remount a directory that is not a mount point, which reaches the permission checks without mounting anything"

	// EPERM is resolved by the capability witness.
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

// keyringCauses maps go-luks2's keyring sentinels to causes, in match order.
var keyringCauses = []struct {
	sentinel error
	cause    Cause
}{
	{dmcrypt.ErrKeyringBlocked, CauseSyscallBlocked},
	{dmcrypt.ErrKeyringUnsupported, CauseKernelUnsupported},
	{dmcrypt.ErrKeyringQuotaExhausted, CauseResourceExhausted},
}

// classifyKeyring turns go-luks2's answer into a finding, or nil when the keyring is usable; unrecognized errors are CauseIndeterminate.
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

// causeForErrno looks an errno up in a table; a non-errno or missing row is CauseIndeterminate.
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

// -----------------------------------------------------------------------------
// CAP_NET_ADMIN, and the DRBD control interface
// -----------------------------------------------------------------------------

// netAdminSteps is the CAP_NET_ADMIN probe: a privileged read and an unprivileged read on the same syscall.
type netAdminSteps struct {
	// privileged issues ETHTOOL_GWOL, which the kernel gates on CAP_NET_ADMIN.
	privileged func(ifname string) error

	// witness issues ETHTOOL_GDRVINFO, allowed without the capability, to show the ioctl path is reachable.
	witness func(ifname string) error
}

// drbdControlSteps is the DRBD control-interface probe.
type drbdControlSteps struct {
	// family resolves a generic-netlink family by name, the way drbdsetup does
	// before it can talk to the module at all.
	family func(name string) error
}

// probeInterface is loopback, which exists in every network namespace; the kernel looks the interface up before checking the capability.
const probeInterface = "lo"

// drbdGenlFamily is the generic-netlink family the drbd kernel module registers.
const drbdGenlFamily = "drbd"

// netAdminProbe issues the read-only ETHTOOL_GWOL on loopback: EOPNOTSUPP means held, EPERM is attributed to the capability only if the witness reaches the driver.
func netAdminProbe(steps netAdminSteps) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityNetAdmin,
				Cause:      CauseIndeterminate,
				Probe:      "starting the CAP_NET_ADMIN probe",
				Err:        err,
			}
		}
		// Tested rather than returned directly, to avoid a typed-nil error.
		if failure := classifyNetAdmin(steps.privileged(probeInterface), func() error {
			return steps.witness(probeInterface)
		}); failure != nil {
			return failure
		}
		return nil
	}
}

// classifyNetAdmin turns the privileged read's answer into a typed finding, or
// nil when CAP_NET_ADMIN is held.
func classifyNetAdmin(err error, witness func() error) *CapabilityError {
	const probe = "issuing the read-only ETHTOOL_GWOL ioctl on " + probeInterface +
		", which the kernel gates on CAP_NET_ADMIN and which configures nothing"

	// The driver was reached; loopback has no wake-on-LAN, so EOPNOTSUPP is success.
	if err == nil || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}

	if errors.Is(err, unix.EPERM) {
		if witness == nil {
			// No witness means the refusal cannot be attributed, and the two
			// candidates have opposite fixes. Reported as the ambiguity rather
			// than resolved by assuming the likelier one.
			return &CapabilityError{
				Capability: CapabilityNetAdmin,
				Cause:      CausePrivilegeOrPolicy,
				Probe:      probe + ", with no witness available to say whether the ioctl path is reachable",
				Err:        err,
			}
		}
		if !isEthtoolReachable(witness()) {
			return &CapabilityError{
				Capability: CapabilityNetAdmin,
				Cause:      CauseSyscallBlocked,
				Probe: probe + ", and an UNPRIVILEGED ethtool read on the same socket was refused too, " +
					"so the ioctl path itself is filtered rather than the capability being absent",
				Err: err,
			}
		}
		return &CapabilityError{
			Capability: CapabilityNetAdmin,
			Cause:      CausePrivilegeMissing,
			Probe: probe + ", and an UNPRIVILEGED ethtool read on the same socket succeeded, " +
				"so the ioctl path is live and the refusal is the capability itself",
			Err: err,
		}
	}

	return &CapabilityError{
		Capability: CapabilityNetAdmin,
		Cause:      CauseIndeterminate,
		Probe:      probe,
		Err:        err,
	}
}

// isEthtoolReachable reports whether the unprivileged witness reached the driver (EOPNOTSUPP or nil).
func isEthtoolReachable(err error) bool {
	return err == nil || errors.Is(err, unix.EOPNOTSUPP)
}

// drbdControlProbe resolves the drbd generic-netlink family by name, a read that creates nothing.
func drbdControlProbe(steps drbdControlSteps) Probe {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityDRBDControl,
				Cause:      CauseIndeterminate,
				Probe:      "starting the DRBD control-interface probe",
				Err:        err,
			}
		}
		// See netAdminProbe: a nil *CapabilityError is not a nil error.
		if failure := classifyDRBDControl(steps.family(drbdGenlFamily)); failure != nil {
			return failure
		}
		return nil
	}
}

// drbdControlCauses maps the family lookup's errno to a cause; ENOENT means the module is not loaded.
var drbdControlCauses = map[unix.Errno]Cause{
	unix.ENOENT:          CauseKernelUnsupported,
	unix.EPERM:           CauseSyscallBlocked,
	unix.EACCES:          CauseSyscallBlocked,
	unix.EAFNOSUPPORT:    CauseKernelUnsupported,
	unix.EPROTONOSUPPORT: CauseKernelUnsupported,
}

// classifyDRBDControl turns the family lookup's answer into a typed finding, or
// nil when the control interface is present.
func classifyDRBDControl(err error) *CapabilityError {
	if err == nil {
		return nil
	}
	return &CapabilityError{
		Capability: CapabilityDRBDControl,
		Cause:      causeForErrno(err, drbdControlCauses),
		Probe: "resolving the " + drbdGenlFamily + " generic-netlink family, which is the first thing " +
			"drbdsetup does and which reads the kernel's own registry without creating anything",
		Err: err,
	}
}

// liveNetAdminSteps talks to the real kernel.
func liveNetAdminSteps() netAdminSteps {
	return netAdminSteps{
		privileged: func(ifname string) error {
			var wol ethtoolWolInfo
			wol.cmd = unix.ETHTOOL_GWOL
			// #nosec G103 -- the kernel's ethtool interface is defined by memory
			// layout; the struct is stack-allocated here and outlives the call.
			return ethtoolIoctl(ifname, unsafe.Pointer(&wol))
		},
		witness: func(ifname string) error {
			// x/sys/unix's own helper, which builds the ifreq correctly and is
			// maintained upstream. Using it here means only ONE hand-rolled
			// ethtool path exists in this package instead of two.
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			_, err = unix.IoctlGetEthtoolDrvinfo(fd, ifname)
			return err
		},
	}
}

// ethtoolWolInfo is the kernel's struct ethtool_wolinfo, the buffer
// ETHTOOL_GWOL reports into.
type ethtoolWolInfo struct {
	cmd       uint32
	supported uint32
	wolopts   uint32
	sopass    [6]byte
	_         [2]byte
}

// ifreqSizes are struct ifreq's dimensions: a 16-byte name and a 24-byte union.
const (
	ifreqUnionBytes = 24
	ifreqTotalBytes = unix.IFNAMSIZ + ifreqUnionBytes
)

// ifreqData is the full 40-byte struct ifreq with a pointer union, as in x/sys/unix, so the kernel's copy-back stays in bounds.
type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [ifreqUnionBytes - unix.SizeofPtr]byte
}

// A build-time assertion that the struct really is the size the kernel expects.
// A silently short ifreq is exactly the defect this replaced, so the size is
// checked by the compiler rather than by the next reader.
var _ [1]struct{} = [unsafe.Sizeof(ifreqData{}) - ifreqTotalBytes + 1]struct{}{}

// ethtoolIoctl issues one ethtool command against an interface.
func ethtoolIoctl(ifname string, data unsafe.Pointer) error {
	if len(ifname) >= unix.IFNAMSIZ {
		return unix.EINVAL
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	ifr := ifreqData{data: data}
	copy(ifr.name[:], ifname)

	// #nosec G103 -- ifr is the kernel's struct ifreq at its full size, stack
	// allocated above and live across the call.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return errno
	}
	return nil
}

// liveDRBDControlSteps talks to the real kernel.
func liveDRBDControlSteps() drbdControlSteps {
	return drbdControlSteps{family: resolveGenlFamily}
}

// Generic-netlink constants. They are part of the kernel's stable uapi and are
// spelled out because x/sys/unix does not export the control-protocol ones.
const (
	genlIDCtrl           = 16 // GENL_ID_CTRL
	genlCtrlCmdGetFamily = 3  // CTRL_CMD_GETFAMILY
	genlCtrlAttrName     = 2  // CTRL_ATTR_FAMILY_NAME
	genlVersion          = 1
	genlNameSize         = 16 // GENL_NAMSIZ
	nlmsgError           = 2  // NLMSG_ERROR
	nlmsgHdrLen          = 16
	genlHdrLen           = 4
	nlAttrHdrLen         = 4
)

// resolveGenlFamily asks the kernel whether a generic-netlink family is registered; fields are native endian, and ENOENT means absent.
func resolveGenlFamily(name string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	// The kernel's GENL_NAMSIZ. A longer name cannot name a registered family,
	// and refusing it here keeps the length arithmetic below provably in range
	// by construction rather than by assertion.
	if len(name) == 0 || len(name) >= genlNameSize {
		return unix.EINVAL
	}

	payload := []byte(name)
	payload = append(payload, 0)
	// #nosec G115 -- len(payload) is at most genlNameSize+1, refused above, so
	// the sum is a small constant and cannot overflow uint16.
	attrLen := uint16(nlAttrHdrLen + len(payload))
	for len(payload)%4 != 0 {
		payload = append(payload, 0)
	}
	// #nosec G115 -- same bound: three compile-time constants plus a payload
	// capped at genlNameSize, so the total is well under uint32.
	msgLen := uint32(nlmsgHdrLen + genlHdrLen + nlAttrHdrLen + len(payload))

	msg := make([]byte, 0, nlmsgHdrLen+genlHdrLen+nlAttrHdrLen+len(payload))
	msg = binary.NativeEndian.AppendUint32(msg, msgLen)
	msg = binary.NativeEndian.AppendUint16(msg, genlIDCtrl)
	msg = binary.NativeEndian.AppendUint16(msg, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg = binary.NativeEndian.AppendUint32(msg, 1) // sequence
	msg = binary.NativeEndian.AppendUint32(msg, 0) // port: kernel assigns
	msg = append(msg, genlCtrlCmdGetFamily, genlVersion, 0, 0)
	msg = binary.NativeEndian.AppendUint16(msg, attrLen)
	msg = binary.NativeEndian.AppendUint16(msg, genlCtrlAttrName)
	msg = append(msg, payload...)

	if sendErr := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); sendErr != nil {
		return sendErr
	}

	reply := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, reply, 0)
	if err != nil {
		return err
	}
	if n < nlmsgHdrLen {
		return errShortNetlinkReply
	}

	// An NLMSG_ERROR carries a negative errno; zero is the ACK for success.
	if binary.NativeEndian.Uint16(reply[4:6]) == nlmsgError {
		if n < nlmsgHdrLen+4 {
			return errShortNetlinkReply
		}
		// The kernel writes a negative errno; zero is the success ACK.
		raw := binary.NativeEndian.Uint32(reply[nlmsgHdrLen : nlmsgHdrLen+4])
		if raw == 0 {
			return nil
		}
		// #nosec G115 -- the kernel writes its errno into this field as a signed
		// 32-bit value; reinterpreting the same four bytes as int32 is reading
		// it in the type it was written in, not a narrowing conversion.
		code := int32(raw)
		if code > 0 {
			return errUnexpectedNetlinkError
		}
		// #nosec G115 -- code is negative here (the positive case returned
		// above), so -code is positive and within errno range.
		return unix.Errno(-code)
	}
	return nil
}

// errShortNetlinkReply reports a netlink reply too short to interpret. It fails
// closed: a reply that cannot be read is not evidence the family is present.
var errShortNetlinkReply = errors.New("the kernel's netlink reply was too short to interpret")

// errUnexpectedNetlinkError reports an NLMSG_ERROR with a positive value; it fails closed.
var errUnexpectedNetlinkError = errors.New("the kernel's netlink error carried a value that is not a negative errno")
