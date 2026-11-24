#!/usr/bin/env bash
# Runs the preflight probe in containers with varied capabilities, seccomp profiles and devices, asserting each row's verdict (usage: scripts/preflight-container-matrix.sh [docker-binary]).
set -euo pipefail

DOCKER="${1:-docker}"
IMAGE="${PREFLIGHT_MATRIX_IMAGE:-alpine:3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v "$DOCKER" >/dev/null 2>&1 || {
	echo "preflight-matrix: $DOCKER is not on PATH; this demonstration needs a container runtime" >&2
	exit 1
}
"$DOCKER" info >/dev/null 2>&1 || {
	echo "preflight-matrix: cannot talk to the container runtime" >&2
	exit 1
}
[ -e /dev/mapper/control ] || {
	echo "preflight-matrix: this host has no /dev/mapper/control, so there is nothing to pass into a container" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# the probe binary: the library's own entry point, nothing simulated
# ---------------------------------------------------------------------------
mkdir -p "$WORK/cmd"
cat >"$WORK/cmd/main.go" <<'GO'
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

func main() {
	wanted := []preflight.Capability{
		preflight.CapabilityDeviceMapper,
		preflight.CapabilityKernelKeyring,
	}
	switch {
	case len(os.Args) > 1 && os.Args[1] == "mount":
		wanted = []preflight.Capability{preflight.CapabilityMount}
	case len(os.Args) > 1 && os.Args[1] == "net-admin":
		wanted = []preflight.Capability{preflight.CapabilityNetAdmin}
	case len(os.Args) > 1 && os.Args[1] == "drbd-control":
		wanted = []preflight.Capability{preflight.CapabilityDRBDControl}
	}

	err := preflight.Check(context.Background(), wanted...)
	if err == nil {
		fmt.Println("PASS")
		return
	}
	fmt.Println("REFUSED")
	fmt.Println(err)
	os.Exit(1)
}
GO

# Build the probe inside the module in a staging directory this script removes; a failed build stops the run.
echo "→ building the probe against this working tree"
STAGE="$ROOT/.preflight-matrix-tmp"
rm -rf "$STAGE"
mkdir -p "$STAGE"
trap 'rm -rf "$WORK" "$STAGE"' EXIT
cp "$WORK/cmd/main.go" "$STAGE/main.go"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/preflight-probe" ./.preflight-matrix-tmp )

# Seccomp profiles: default-deny with an explicit allow list, including the socket families the replicated backend needs.
KEYRING_SYSCALLS='"add_key","keyctl","request_key",'
BASE_SYSCALLS='
"arch_prctl","brk","capget","capset","chdir","clone","clone3","close","dup","dup2","dup3",
"epoll_create1","epoll_ctl","epoll_pwait","eventfd2","execve","exit","exit_group","faccessat2",
"fchdir","fchown","fcntl","fstat","fstatfs","futex","getcwd","getdents64","getegid","geteuid",
"getgid","getpgid","getpid","getppid","getrandom","gettid","getuid","ioctl","madvise","mkdirat",
"mlock","mmap","mount","mprotect","munlock","munmap","nanosleep","newfstatat","openat","openat2",
"pipe2","pivot_root","prctl","pread64","prlimit64","read","readlinkat","rseq","rt_sigaction",
"rt_sigprocmask","rt_sigreturn","sched_getaffinity","sched_yield","set_robust_list",
"set_tid_address","setgid","setgroups","sethostname","setsid","setuid","sigaltstack","statfs",
"statx","tgkill","timer_create","timer_delete","timer_settime","umask","umount2","uname",
"unlinkat","wait4","write","writev",
"socket","socketpair","bind","connect","sendto","recvfrom","getsockname","getsockopt","setsockopt"'

profile() { # $1 = output path, $2 = extra syscalls (may be empty)
	cat >"$1" <<EOF
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]
    },
    {
      "architecture": "SCMP_ARCH_AARCH64",
      "subArchitectures": ["SCMP_ARCH_ARM"]
    }
  ],
  "syscalls": [
    { "names": [ $2 $BASE_SYSCALLS ], "action": "SCMP_ACT_ALLOW" }
  ]
}
EOF
}

profile "$WORK/narrow.json" "$KEYRING_SYSCALLS"
profile "$WORK/narrow-without-keyring.json" ""

# The same narrow profile with mount(2) removed, to isolate a seccomp denial of
# mount from an LSM denial of it.
FULL_BASE="$BASE_SYSCALLS"
BASE_SYSCALLS="$(printf '%s' "$FULL_BASE" | sed 's/"mount",//')"
profile "$WORK/narrow-without-mount.json" "$KEYRING_SYSCALLS"

# And with ioctl removed, which is how a seccomp denial of the device-mapper
# check is told apart from a missing capability: the kernel's own capability
# check answers EACCES, a seccomp filter answers EPERM.
BASE_SYSCALLS="$(printf '%s' "$FULL_BASE" | sed 's/"ioctl",//')"
profile "$WORK/narrow-without-ioctl.json" "$KEYRING_SYSCALLS"
BASE_SYSCALLS="$FULL_BASE"

# ---------------------------------------------------------------------------
# the matrix
# ---------------------------------------------------------------------------
failures=0

run_case() { # $1 = name, $2 = expected PASS|REFUSED, $3 = expected substring, $4 = probe mode, rest = docker args
	local name="$1" expect="$2" needle="$3" mode="$4"
	shift 4

	local output status
	set +e
	# --user 0 first; docker takes the last --user, so a row can override it.
	output="$("$DOCKER" run --rm \
		-v "$WORK/preflight-probe:/preflight-probe:ro" \
		--user 0 "$@" "$IMAGE" /preflight-probe "$mode" 2>&1)"
	status=$?
	set -e

	local verdict="REFUSED"
	[ "$status" -eq 0 ] && verdict="PASS"

	if [ "$verdict" != "$expect" ]; then
		echo "✗ $name: got $verdict, expected $expect"
		echo "$output" | sed 's/^/    /'
		failures=$((failures + 1))
		return
	fi
	if [ -n "$needle" ] && ! printf '%s' "$output" | grep -qF "$needle"; then
		echo "✗ $name: the $verdict did not mention '$needle'"
		echo "$output" | sed 's/^/    /'
		failures=$((failures + 1))
		return
	fi
	echo "✓ $name: $verdict"
}

echo
echo "→ the matrix"

run_case "no capabilities, default seccomp" REFUSED "device-mapper is unavailable" dm-keyring

run_case "CAP_SYS_ADMIN + the device, DEFAULT seccomp (the trap)" \
	REFUSED "kernel-keyring is unavailable" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control

run_case "the same, minus the keyring syscalls (mutation)" \
	REFUSED "kernel-keyring is unavailable" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow-without-keyring.json"

run_case "CAP_SYS_ADMIN + the device + a NARROW profile allowing the three" \
	PASS "" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

# mount(2) rows: the three verdicts of the device-mapper capability witness.
run_case "mount denied by the default AppArmor profile, with the capability held" \
	REFUSED "[lsm-denied]" mount \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "mount denied by seccomp, with the capability WITNESSED as held" \
	REFUSED "[syscall-blocked]" mount \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt apparmor=unconfined \
	--security-opt seccomp="$WORK/narrow-without-mount.json"

run_case "mount denied with no witness available, reported as ambiguous" \
	REFUSED "[privilege-or-policy]" mount \
	--security-opt apparmor=unconfined

# Device-mapper rows: EACCES from the handler's capability check, EPERM from seccomp.
run_case "device-mapper denied by the kernel capability check (EACCES)" \
	REFUSED "[privilege-missing]" dm-keyring \
	--device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "device-mapper denied by seccomp on ioctl (EPERM), capability held" \
	REFUSED "[syscall-blocked]" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow-without-ioctl.json"

# Device node rows: visible but not allowed by the device cgroup, and refused by node permissions.
run_case "the node is bind-mounted but not allowed by the device cgroup" \
	REFUSED "[device-access-denied]" dm-keyring \
	--cap-add SYS_ADMIN -v /dev/mapper/control:/dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "the node is allowed but the storage component runs as a non-root uid" \
	REFUSED "[device-not-readable]" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json" --user 65534

# Replicated backend rows: CAP_NET_ADMIN is independent of device-mapper access.
run_case "CAP_SYS_ADMIN but no CAP_NET_ADMIN: device-mapper works, DRBD cannot" \
	REFUSED "[privilege-missing]" net-admin \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "--cap-add NET_ADMIN, which is what the replicated backend needs" \
	PASS "" net-admin \
	--cap-add NET_ADMIN \
	--security-opt seccomp="$WORK/narrow.json"

# And the module, which is NOT a privilege: no capability grant loads it, so the
# refusal must send an operator to the node rather than to a container flag.
run_case "the drbd module is not loaded, which no capability can fix" \
	REFUSED "modprobe drbd" drbd-control \
	--cap-add NET_ADMIN --cap-add SYS_ADMIN \
	--security-opt seccomp="$WORK/narrow.json"

echo
if [ "$failures" -ne 0 ]; then
	echo "✗ $failures row(s) did not behave as the guard claims"
	exit 1
fi
echo "✓ the guard refuses every misconfigured container and passes the correct one"
