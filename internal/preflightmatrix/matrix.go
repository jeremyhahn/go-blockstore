// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package preflightmatrix proves the startup privilege guard in pkg/preflight
// fires — and does NOT fire — in real containers. `make preflight-matrix`
// runs it through cmd/preflight-matrix.
//
// # Why containers and not a unit test
//
// The condition the guard exists to catch cannot be produced inside `go test`.
// It is a property of how the PROCESS WAS STARTED: a container holding
// CAP_SYS_ADMIN, with /dev/mapper/control passed in, under the runtime's
// DEFAULT seccomp profile. Device-mapper works there. The kernel keyring does
// not. No fixture reachable from a test binary can reproduce that, so a green
// unit suite says nothing about it.
//
// So the demonstration starts the containers, and it ASSERTS rather than
// prints: every row states the expected verdict, and a row that does not match
// is a failure. Run it after changing anything in pkg/preflight.
//
// # What it proves
//
//  1. cap SYS_ADMIN + the device, DEFAULT seccomp → the guard REFUSES, naming
//     the kernel keyring. This is the trap: device-mapper works, so the
//     container looks correctly privileged.
//  2. the same, plus a NARROW seccomp profile that adds add_key, keyctl and
//     request_key → the guard PASSES. Without this row the guard could be one
//     that refuses everything.
//  3. the narrow profile with those three syscalls REMOVED → refuses again.
//     That is the mutation: the pass in row 2 is caused by the allowance.
//  4. no capabilities at all → refuses, naming device-mapper.
//  5. the three verdicts the mount(2) capability witness can reach: an LSM
//     denial, a seccomp denial with the capability PROVEN held, and an EPERM
//     with no witness, reported as ambiguous rather than guessed.
//  6. the same errno split for device-mapper: the kernel's own capability
//     check answers EACCES, a seccomp denial of ioctl answers EPERM.
//  7. opening the node can fail for reasons that are neither the capability
//     nor a filter — a node visible but not allowed by the device cgroup, and
//     a node whose 0600 permissions refuse a non-root uid.
//  8. the REPLICATED backend: CAP_NET_ADMIN refused and then granted, and the
//     drbd module absent — which no capability grant can fix.
//
// The narrow profile is generated rather than committed, so it cannot rot
// against the syscalls the binary actually makes, and so nothing in this
// repository looks like a profile to copy verbatim into production. A real
// deployment takes ITS OWN runtime's default profile and adds the three
// syscalls; see pkg/preflight/doc.go.
//
// --privileged appears in no row on purpose. It would make every row pass and
// prove nothing, and it is not a remedy this project offers.
package preflightmatrix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// Verdict is what the probe reports about a container.
type Verdict string

const (
	// Pass means the guard let the process start.
	Pass Verdict = "PASS"

	// Refused means the guard stopped it.
	Refused Verdict = "REFUSED"
)

// Probe modes: which capabilities the probe binary asks the guard for.
const (
	ModeDMKeyring   = "dm-keyring"
	ModeMount       = "mount"
	ModeNetAdmin    = "net-admin"
	ModeDRBDControl = "drbd-control"
)

// ProbeCapabilities maps a probe mode to the capabilities it checks. Anything
// unrecognized is the default, device-mapper plus the kernel keyring: what the
// local provider needs.
func ProbeCapabilities(mode string) []preflight.Capability {
	switch mode {
	case ModeMount:
		return []preflight.Capability{preflight.CapabilityMount}
	case ModeNetAdmin:
		return []preflight.Capability{preflight.CapabilityNetAdmin}
	case ModeDRBDControl:
		return []preflight.Capability{preflight.CapabilityDRBDControl}
	default:
		return []preflight.Capability{preflight.CapabilityDeviceMapper, preflight.CapabilityKernelKeyring}
	}
}

// Probe is the probe binary's body: it runs the guard for mode through check,
// prints PASS or REFUSED and the refusal, and returns the exit status. The
// library's own entry point is what runs in the container; nothing is
// simulated.
func Probe(ctx context.Context, mode string, check func(context.Context, ...preflight.Capability) error, out io.Writer) int {
	if err := check(ctx, ProbeCapabilities(mode)...); err != nil {
		fmt.Fprintf(out, "%s\n%v\n", Refused, err)
		return 1
	}
	fmt.Fprintf(out, "%s\n", Pass)
	return 0
}

// keyringSyscalls are the three the kernel keyring needs and the runtime's
// default seccomp profile denies.
var keyringSyscalls = []string{"add_key", "keyctl", "request_key"}

// baseSyscalls is the narrow profile's allow list: what the probe binary and
// the container's own start-up make. The socket family at the end is NOT
// decoration: the replicated backend reaches the DRBD module over generic
// netlink and tests CAP_NET_ADMIN with an ethtool ioctl on an AF_INET socket,
// so a profile sized for the LOCAL provider denies both.
var baseSyscalls = []string{
	"arch_prctl", "brk", "capget", "capset", "chdir", "clone", "clone3", "close", "dup", "dup2", "dup3",
	"epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "execve", "exit", "exit_group", "faccessat2",
	"fchdir", "fchown", "fcntl", "fstat", "fstatfs", "futex", "getcwd", "getdents64", "getegid", "geteuid",
	"getgid", "getpgid", "getpid", "getppid", "getrandom", "gettid", "getuid", "ioctl", "madvise", "mkdirat",
	"mlock", "mmap", "mount", "mprotect", "munlock", "munmap", "nanosleep", "newfstatat", "openat", "openat2",
	"pipe2", "pivot_root", "prctl", "pread64", "prlimit64", "read", "readlinkat", "rseq", "rt_sigaction",
	"rt_sigprocmask", "rt_sigreturn", "sched_getaffinity", "sched_yield", "set_robust_list",
	"set_tid_address", "setgid", "setgroups", "sethostname", "setsid", "setuid", "sigaltstack", "statfs",
	"statx", "tgkill", "timer_create", "timer_delete", "timer_settime", "umask", "umount2", "uname",
	"unlinkat", "wait4", "write", "writev",
	"socket", "socketpair", "bind", "connect", "sendto", "recvfrom", "getsockname", "getsockopt", "setsockopt",
}

// seccompProfile is the JSON shape the container runtime reads.
type seccompProfile struct {
	DefaultAction   string         `json:"defaultAction"`
	DefaultErrnoRet int            `json:"defaultErrnoRet"`
	ArchMap         []seccompArch  `json:"archMap"`
	Syscalls        []seccompAllow `json:"syscalls"`
}

type seccompArch struct {
	Architecture     string   `json:"architecture"`
	SubArchitectures []string `json:"subArchitectures"`
}

type seccompAllow struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// Profile renders a default-DENY seccomp profile allowing the base syscalls,
// the keyring syscalls when keyring is set, and none of drop. Default-deny with
// an explicit allow list is narrow in the direction that matters, and small
// enough to read.
func Profile(keyring bool, drop ...string) ([]byte, error) {
	var names []string
	if keyring {
		names = append(names, keyringSyscalls...)
	}
	for _, name := range baseSyscalls {
		if !slices.Contains(drop, name) {
			names = append(names, name)
		}
	}
	return json.MarshalIndent(seccompProfile{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: 1,
		ArchMap: []seccompArch{
			{Architecture: "SCMP_ARCH_X86_64", SubArchitectures: []string{"SCMP_ARCH_X86", "SCMP_ARCH_X32"}},
			{Architecture: "SCMP_ARCH_AARCH64", SubArchitectures: []string{"SCMP_ARCH_ARM"}},
		},
		Syscalls: []seccompAllow{{Names: names, Action: "SCMP_ACT_ALLOW"}},
	}, "", "  ")
}

// Profiles are the paths of the generated seccomp profiles.
type Profiles struct {
	// Narrow allows the keyring syscalls: the correct profile.
	Narrow string

	// WithoutKeyring is Narrow minus the keyring syscalls: the mutation.
	WithoutKeyring string

	// WithoutMount is Narrow minus mount(2), isolating a seccomp denial of
	// mount from an LSM denial of it.
	WithoutMount string

	// WithoutIoctl is Narrow minus ioctl, which is how a seccomp denial of the
	// device-mapper check is told apart from a missing capability.
	WithoutIoctl string
}

// WriteProfiles generates the four profiles into dir.
func WriteProfiles(dir string) (Profiles, error) {
	profiles := Profiles{
		Narrow:         filepath.Join(dir, "narrow.json"),
		WithoutKeyring: filepath.Join(dir, "narrow-without-keyring.json"),
		WithoutMount:   filepath.Join(dir, "narrow-without-mount.json"),
		WithoutIoctl:   filepath.Join(dir, "narrow-without-ioctl.json"),
	}
	for _, p := range []struct {
		path    string
		keyring bool
		drop    []string
	}{
		{profiles.Narrow, true, nil},
		{profiles.WithoutKeyring, false, nil},
		{profiles.WithoutMount, true, []string{"mount"}},
		{profiles.WithoutIoctl, true, []string{"ioctl"}},
	} {
		content, err := Profile(p.keyring, p.drop...)
		if err != nil {
			return Profiles{}, &ProfileError{Path: p.path, Err: err}
		}
		if err := os.WriteFile(p.path, content, 0o600); err != nil {
			return Profiles{}, &ProfileError{Path: p.path, Err: err}
		}
	}
	return profiles, nil
}

// Case is one row of the matrix: a container configuration and the verdict the
// guard must reach in it.
type Case struct {
	// Name says what the row demonstrates.
	Name string

	// Expect is the verdict the guard must reach.
	Expect Verdict

	// Needle must appear in the probe's output; empty means no requirement.
	Needle string

	// Mode is the probe mode.
	Mode string

	// Args are the container runtime flags that make the configuration.
	Args []string
}

// Cases is the matrix. --privileged appears in none of it.
func Cases(p Profiles) []Case {
	const (
		dmControl = "/dev/mapper/control"
	)
	sysAdmin := []string{"--cap-add", "SYS_ADMIN", "--device", dmControl}
	with := func(base []string, more ...string) []string {
		return append(slices.Clone(base), more...)
	}
	seccomp := func(path string) []string { return []string{"--security-opt", "seccomp=" + path} }

	return []Case{
		{Name: "no capabilities, default seccomp", Expect: Refused,
			Needle: "device-mapper is unavailable", Mode: ModeDMKeyring},
		{Name: "CAP_SYS_ADMIN + the device, DEFAULT seccomp (the trap)", Expect: Refused,
			Needle: "kernel-keyring is unavailable", Mode: ModeDMKeyring, Args: sysAdmin},
		{Name: "the same, minus the keyring syscalls (mutation)", Expect: Refused,
			Needle: "kernel-keyring is unavailable", Mode: ModeDMKeyring,
			Args: with(sysAdmin, seccomp(p.WithoutKeyring)...)},
		{Name: "CAP_SYS_ADMIN + the device + a NARROW profile allowing the three", Expect: Pass,
			Mode: ModeDMKeyring, Args: with(sysAdmin, seccomp(p.Narrow)...)},

		// mount(2) answers EPERM for a missing capability AND for a seccomp
		// denial, so the guard witnesses the capability with a device-mapper
		// ioctl rather than guessing. These are the three verdicts that
		// witness can reach.
		{Name: "mount denied by the default AppArmor profile, with the capability held", Expect: Refused,
			Needle: "[lsm-denied]", Mode: ModeMount, Args: with(sysAdmin, seccomp(p.Narrow)...)},
		{Name: "mount denied by seccomp, with the capability WITNESSED as held", Expect: Refused,
			Needle: "[syscall-blocked]", Mode: ModeMount,
			Args: with(sysAdmin, append([]string{"--security-opt", "apparmor=unconfined"}, seccomp(p.WithoutMount)...)...)},
		{Name: "mount denied with no witness available, reported as ambiguous", Expect: Refused,
			Needle: "[privilege-or-policy]", Mode: ModeMount, Args: []string{"--security-opt", "apparmor=unconfined"}},

		// The same errno split one layer down.
		{Name: "device-mapper denied by the kernel capability check (EACCES)", Expect: Refused,
			Needle: "[privilege-missing]", Mode: ModeDMKeyring,
			Args: with([]string{"--device", dmControl}, seccomp(p.Narrow)...)},
		{Name: "device-mapper denied by seccomp on ioctl (EPERM), capability held", Expect: Refused,
			Needle: "[syscall-blocked]", Mode: ModeDMKeyring, Args: with(sysAdmin, seccomp(p.WithoutIoctl)...)},

		// Opening the node fails for reasons that are neither the capability
		// nor a filter, and each has its own fix. A node made VISIBLE without
		// being ALLOWED is the mistake a Kubernetes hostPath walks into.
		{Name: "the node is bind-mounted but not allowed by the device cgroup", Expect: Refused,
			Needle: "[device-access-denied]", Mode: ModeDMKeyring,
			Args: with([]string{"--cap-add", "SYS_ADMIN", "-v", dmControl + ":" + dmControl}, seccomp(p.Narrow)...)},
		{Name: "the node is allowed but the storage component runs as a non-root uid", Expect: Refused,
			Needle: "[device-not-readable]", Mode: ModeDMKeyring,
			Args: with(sysAdmin, append(seccomp(p.Narrow), "--user", "65534")...)},

		// The REPLICATED backend needs a capability the local one does not.
		{Name: "CAP_SYS_ADMIN but no CAP_NET_ADMIN: device-mapper works, DRBD cannot", Expect: Refused,
			Needle: "[privilege-missing]", Mode: ModeNetAdmin, Args: with(sysAdmin, seccomp(p.Narrow)...)},
		{Name: "--cap-add NET_ADMIN, which is what the replicated backend needs", Expect: Pass,
			Mode: ModeNetAdmin, Args: with([]string{"--cap-add", "NET_ADMIN"}, seccomp(p.Narrow)...)},

		// And the module, which is NOT a privilege: no capability grant loads
		// it, so the refusal must send an operator to the node.
		{Name: "the drbd module is not loaded, which no capability can fix", Expect: Refused,
			Needle: "modprobe drbd", Mode: ModeDRBDControl,
			Args: with([]string{"--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN"}, seccomp(p.Narrow)...)},
	}
}

// Container runs one container to completion. passed reports a zero exit; err
// is reserved for a runtime that could not be run at all, which is not a
// verdict about the guard.
type Container func(ctx context.Context, args []string) (output string, passed bool, err error)

// Run executes every case in image with the probe binary mounted in, and writes
// one line per row. It returns the number of rows that did not behave as the
// guard claims. There is no fallback anywhere: a row that cannot be run stops
// the matrix.
func Run(ctx context.Context, run Container, image, probe string, cases []Case, w io.Writer) (int, error) {
	failures := 0
	for _, c := range cases {
		// --user 0 first so a row that passes its own --user overrides it:
		// the runtime takes the LAST occurrence.
		args := []string{"run", "--rm", "-v", probe + ":/preflight-probe:ro", "--user", "0"}
		args = append(args, c.Args...)
		args = append(args, image, "/preflight-probe", c.Mode)

		output, passed, err := run(ctx, args)
		if err != nil {
			return failures, &RowError{Row: c.Name, Err: err}
		}
		verdict := Refused
		if passed {
			verdict = Pass
		}
		switch {
		case verdict != c.Expect:
			fmt.Fprintf(w, "✗ %s: got %s, expected %s\n%s", c.Name, verdict, c.Expect, indent(output))
			failures++
		case c.Needle != "" && !strings.Contains(output, c.Needle):
			fmt.Fprintf(w, "✗ %s: the %s did not mention %q\n%s", c.Name, verdict, c.Needle, indent(output))
			failures++
		default:
			fmt.Fprintf(w, "✓ %s: %s\n", c.Name, verdict)
		}
	}
	return failures, nil
}

// indent prefixes every line of a container's output for the report.
func indent(output string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}
