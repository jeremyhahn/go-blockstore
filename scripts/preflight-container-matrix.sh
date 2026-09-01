#!/usr/bin/env bash
# Prove the startup privilege guard fires — and does NOT fire — in real
# containers.
#
#   usage: scripts/preflight-container-matrix.sh [docker-binary]
#
# WHY A SCRIPT AND NOT A UNIT TEST
# --------------------------------
# The condition the guard exists to catch cannot be produced inside `go test`.
# It is a property of how the PROCESS WAS STARTED: a container holding
# CAP_SYS_ADMIN, with /dev/mapper/control passed in, under the runtime's DEFAULT
# seccomp profile. Device-mapper works there. The kernel keyring does not. No
# fixture reachable from a test binary can reproduce that, so a green unit suite
# says nothing about it — and green tests have been false evidence for exactly
# this class of claim before.
#
# So the demonstration is a script that starts the containers, and it ASSERTS
# rather than prints: every row states the expected verdict, and a row that does
# not match exits non-zero. Run it after changing anything in pkg/preflight.
#
# WHAT IT PROVES
# --------------
#   1. cap SYS_ADMIN + the device, DEFAULT seccomp  → the guard REFUSES, naming
#      the kernel keyring. This is the trap: device-mapper works, so the
#      container looks correctly privileged.
#   2. the same, plus a NARROW seccomp profile that adds add_key, keyctl and
#      request_key → the guard PASSES. Without this row the guard could be one
#      that refuses everything.
#   3. the narrow profile with those three syscalls REMOVED → refuses again.
#      That is the mutation: the pass in row 2 is caused by the allowance and
#      not by anything else about the profile.
#   4. no capabilities at all → refuses, naming device-mapper as well.
#   5-7. the three verdicts the mount(2) capability witness can reach: an LSM
#      denial, a seccomp denial with the capability PROVEN held, and an EPERM
#      with no witness available reported as ambiguous rather than guessed.
#   8-9. the same errno split for device-mapper itself: the kernel's own
#      capability check answers EACCES, a seccomp denial of ioctl answers EPERM,
#      and the two get different remedies.
#   10-11. opening the node can fail for reasons that are neither the capability
#      nor a filter — a node made visible without being allowed by the device
#      cgroup, and a node whose own 0600 permissions refuse a non-root uid.
#
# The narrow profile is generated here rather than committed, so it cannot rot
# against the syscalls the binary actually makes, and so that nothing in this
# repository looks like a profile to copy verbatim into production. A real
# deployment takes ITS OWN runtime's default profile and adds the three
# syscalls; see pkg/preflight/doc.go.
#
# --privileged appears nowhere in this file on purpose. It would make every row
# pass and prove nothing, and it is not a remedy this project offers.
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
	if len(os.Args) > 1 && os.Args[1] == "mount" {
		wanted = []preflight.Capability{preflight.CapabilityMount}
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

# The probe has to be built INSIDE the module to import it, so it is staged in
# a directory this script owns and removes. There is no `|| true` and no
# fallback anywhere in this file: a build that fails must stop the run, because
# a matrix that silently ran an old binary would be worse than no matrix.
echo "→ building the probe against this working tree"
STAGE="$ROOT/.preflight-matrix-tmp"
rm -rf "$STAGE"
mkdir -p "$STAGE"
trap 'rm -rf "$WORK" "$STAGE"' EXIT
cp "$WORK/cmd/main.go" "$STAGE/main.go"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/preflight-probe" ./.preflight-matrix-tmp )

# ---------------------------------------------------------------------------
# the seccomp profiles
# ---------------------------------------------------------------------------
# Default-DENY with an explicit allow list: narrow in the direction that
# matters, and small enough to read. The syscalls are the ones the probe binary
# and the container's own start-up make.
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
"unlinkat","wait4","write","writev"'

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
	# --user 0 first so a row that passes its own --user overrides it: docker
	# takes the LAST occurrence, which is what lets row 11 run as a non-root uid.
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

# mount(2) answers EPERM for a missing capability AND for a seccomp denial, so
# the guard witnesses the capability with a device-mapper ioctl rather than
# guessing. These three rows are the three verdicts that witness can reach; the
# middle one is the misclassification the first draft shipped, where a container
# that HELD CAP_SYS_ADMIN was told to grant it.
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

# The same errno split one layer down. The device-mapper ioctl handler's own
# capability check answers EACCES; a seccomp filter denying ioctl answers EPERM
# before that handler runs. Reading EPERM as a missing capability would tell an
# operator holding CAP_SYS_ADMIN to grant it.
run_case "device-mapper denied by the kernel capability check (EACCES)" \
	REFUSED "[privilege-missing]" dm-keyring \
	--device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "device-mapper denied by seccomp on ioctl (EPERM), capability held" \
	REFUSED "[syscall-blocked]" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow-without-ioctl.json"

# Opening the node fails for reasons that are neither the capability nor a
# syscall filter, and each has its own fix. A node made VISIBLE without being
# ALLOWED is the mistake a Kubernetes hostPath walks straight into.
run_case "the node is bind-mounted but not allowed by the device cgroup" \
	REFUSED "[device-access-denied]" dm-keyring \
	--cap-add SYS_ADMIN -v /dev/mapper/control:/dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json"

run_case "the node is allowed but the storage component runs as a non-root uid" \
	REFUSED "[device-not-readable]" dm-keyring \
	--cap-add SYS_ADMIN --device /dev/mapper/control \
	--security-opt seccomp="$WORK/narrow.json" --user 65534

echo
if [ "$failures" -ne 0 ]; then
	echo "✗ $failures row(s) did not behave as the guard claims"
	exit 1
fi
echo "✓ the guard refuses every misconfigured container and passes the correct one"
