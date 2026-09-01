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

//go:build drbd

package drbd

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// These exercise the production runner against real processes. Everything else
// in the package runs on the scripted fake, which would happily pass over a
// runner that lost stderr, reported the wrong exit code, or never execed at
// all — and the exit code in particular is load-bearing: findmnt says "not
// found" with 1 and blkid with 2, so a runner that flattened both to "error"
// would turn an unmounted target into a failure and an empty device into an
// unreadable one.
//
// /bin/sh is the only external dependency, and this package already requires a
// Linux node with drbd-utils and LVM.

const (
	testShell      = "/bin/sh"
	testMissingBin = "go-blockstore-no-such-binary-9f3a"
)

// testRunner drives real processes without widening what the provider itself
// may exec: the allowlist the production runner uses is asserted separately,
// in TestAllowedBinariesCoversEveryProgramWeRun.
func testRunner() execRunner {
	return execRunner{allow: map[string]struct{}{testShell: {}, testMissingBin: {}}}
}

func TestExecRunnerCapturesStdout(t *testing.T) {
	out, err := testRunner().Run(context.Background(), testShell, "-c", "printf 'hello world'")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := string(out); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
}

// TestExecRunnerForcesTheCLocale keeps a localized host from reformatting the
// lvs output this package parses.
//
// data_percent is the field that actually breaks: it goes through
// strconv.ParseFloat, and a locale that writes "12,34" makes that read zero, so
// ListSnapshots would report every snapshot as occupying nothing. The byte
// counts are integers and would come through fine, which is what makes the
// failure quiet enough to be worth pinning at the source.
func TestExecRunnerForcesTheCLocale(t *testing.T) {
	for _, v := range []string{"LC_ALL", "LANG"} {
		out, err := testRunner().Run(context.Background(), testShell, "-c", `printf '%s' "$`+v+`"`)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := string(out); got != "C" {
			t.Errorf("%s = %q, want C", v, got)
		}
	}
}

// TestExecRunnerReportsExitCode is the property the findmnt and blkid callers
// depend on.
func TestExecRunnerReportsExitCode(t *testing.T) {
	for _, want := range []int{1, 2, 3, 42} {
		_, err := testRunner().Run(context.Background(), testShell, "-c", "exit "+itoa(want))
		if err == nil {
			t.Fatalf("Run exiting %d returned no error", want)
		}
		got, ok := exitCode(err)
		if !ok {
			t.Fatalf("error is not a *CommandError: %T %v", err, err)
		}
		if got != want {
			t.Errorf("ExitCode = %d, want %d", got, want)
		}
	}
}

func TestExecRunnerCapturesStderrAndStdoutOnFailure(t *testing.T) {
	out, err := testRunner().Run(context.Background(), testShell, "-c",
		"printf 'partial'; printf 'it broke' >&2; exit 7")
	if err == nil {
		t.Fatal("Run returned no error")
	}

	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a *CommandError: %T", err)
	}
	if ce.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", ce.ExitCode)
	}
	if ce.Stderr != "it broke" {
		t.Errorf("Stderr = %q, want %q", ce.Stderr, "it broke")
	}
	if ce.Cmd != testShell {
		t.Errorf("Cmd = %q, want %q", ce.Cmd, testShell)
	}
	// Whatever the command managed to write before failing is still returned,
	// so a caller that can use a partial result is not denied it.
	if string(out) != "partial" {
		t.Errorf("stdout = %q, want %q", out, "partial")
	}
	// The diagnostic has to name the command and carry what it said, or a
	// drbdadm refusal reaches the operator as a bare exit status.
	msg := ce.Error()
	for _, want := range []string{testShell, "exit status 7", "it broke"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
}

// TestExecRunnerCommandThatCannotStart covers the other failure shape: not a
// process that exited badly, but one that never ran.
func TestExecRunnerCommandThatCannotStart(t *testing.T) {
	_, err := testRunner().Run(context.Background(), testMissingBin)
	if err == nil {
		t.Fatal("Run of a nonexistent binary returned no error")
	}

	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a *CommandError: %T", err)
	}
	if ce.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1 for a command that never ran", ce.ExitCode)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("the exec error should survive Unwrap: %v", err)
	}
	if !strings.Contains(ce.Error(), testMissingBin) {
		t.Errorf("Error() = %q, want it to name the binary", ce.Error())
	}
}

// TestExecRunnerCancellation checks that a canceled context reaches the caller
// as context.Canceled rather than as the "signal: killed" the kill produces,
// which says nothing about why.
func TestExecRunnerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := testRunner().Run(ctx, testShell, "-c", "exit 0")
	if err == nil {
		t.Fatal("Run with a canceled context returned no error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestCommandErrorUnwrap(t *testing.T) {
	inner := errors.New("underneath")
	ce := &CommandError{Cmd: "drbdadm", Args: []string{"primary", "vol1"}, ExitCode: 11, Err: inner}

	if !errors.Is(ce, inner) {
		t.Error("Unwrap does not expose the wrapped error")
	}
	if got := ce.Error(); !strings.Contains(got, "drbdadm primary vol1") {
		t.Errorf("Error() = %q, want the full argv", got)
	}

	// A command that never ran has no exit status to report, so the underlying
	// error is what the message carries instead.
	nostart := &CommandError{Cmd: "drbdadm", ExitCode: -1, Err: inner}
	if got := nostart.Error(); !strings.Contains(got, "underneath") || strings.Contains(got, "exit status") {
		t.Errorf("Error() = %q, want the cause and no exit status", got)
	}
}

func TestExitCodeOnAnUnrelatedError(t *testing.T) {
	if _, ok := exitCode(errors.New("not a command error")); ok {
		t.Error("exitCode claimed an unrelated error carried an exit status")
	}
	if _, ok := exitCode(nil); ok {
		t.Error("exitCode claimed a nil error carried an exit status")
	}
}

func TestTrimStderr(t *testing.T) {
	if got := trimStderr("  spaced  \n"); got != "spaced" {
		t.Errorf("trimStderr = %q, want %q", got, "spaced")
	}
	if got := trimStderr(""); got != "" {
		t.Errorf("trimStderr of empty = %q, want empty", got)
	}

	// A tool spewing output must not turn an error value into a memory problem.
	long := strings.Repeat("x", maxStderr*3)
	got := trimStderr(long)
	if len(got) <= maxStderr || !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("trimStderr of %d bytes returned %d bytes ending %q", len(long), len(got), got[max(0, len(got)-16):])
	}
	if len(got) > maxStderr+len("…(truncated)") {
		t.Errorf("truncated output is %d bytes, want about %d", len(got), maxStderr)
	}
}

// itoa keeps the shell arguments above free of a strconv import in a file
// otherwise about process behavior.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestAllowedBinariesCoversEveryProgramWeRun keeps the allowlist and the call
// sites from drifting. The allowlist is only enforced in the production
// runner, which the rest of the suite substitutes away, so without this a
// program added to the package would fail for the first time on a real node.
func TestAllowedBinariesCoversEveryProgramWeRun(t *testing.T) {
	for _, bin := range []string{
		binDRBDAdm, binDRBDSetup, binLVCreate, binLVRemove, binLVExtend, binLVS,
		binBlkid, binResize2fs, binXFSGrowfs, binE2fsck, binLVChange,
	} {
		if _, ok := allowedBinaries[bin]; !ok {
			t.Errorf("%q is run by this package but is not in allowedBinaries", bin)
		}
	}
	// mkfs.<type> is built from the filesystem allowlist, so the two lists have
	// to agree or a supported filesystem is one the runner refuses to create.
	for fsType := range supportedFilesystems {
		if _, ok := allowedBinaries["mkfs."+fsType]; !ok {
			t.Errorf("filesystem %q is supported but mkfs.%s is not in allowedBinaries", fsType, fsType)
		}
	}
}

// TestExecRunnerRefusesAnUnlistedBinary is the check that makes the exec call
// something other than an arbitrary subprocess launcher.
func TestExecRunnerRefusesAnUnlistedBinary(t *testing.T) {
	// The zero value is what New builds: the real allowlist, no override.
	_, err := execRunner{}.Run(context.Background(), testShell, "-c", "exit 0")
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Run of an unlisted binary = %v, want common.ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), testShell) {
		t.Errorf("error %q does not name the refused binary", err)
	}
	// It is refused before anything is spawned.
	var ce *CommandError
	if !errors.As(err, &ce) || ce.ExitCode != -1 {
		t.Errorf("error = %v, want a *CommandError with no exit status", err)
	}
}
