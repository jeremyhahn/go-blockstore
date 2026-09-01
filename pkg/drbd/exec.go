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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// CommandRunner executes an external command and returns its standard output.
//
// It is the single seam through which this package touches the system: drbdadm,
// drbdsetup, the LVM tools, mount and friends all go through it, so unit tests
// substitute a scripted implementation and never require DRBD, LVM or root.
//
// Implementations MUST exec the named binary directly with args as separate
// argv elements. Passing the call through a shell would defeat the validation
// this package performs on caller-supplied strings.
//
// A command that exits non-zero must be reported as a *CommandError so callers
// can branch on the exit code — several system tools use the exit code as a
// primary result rather than as a failure signal (findmnt reports "not found"
// with 1, blkid with 2).
//
// NOTE: this seam is duplicated. pkg/local defines an equivalent one for the
// same reason, and neither can import the other without pkg/common growing a
// dependency this package is not free to add. Unifying them in pkg/common is
// left to the HA wave; see the report on issue #3.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// CommandError reports an external command that failed or exited non-zero.
type CommandError struct {
	// Cmd is the binary that was executed.
	Cmd string

	// Args are the arguments it was executed with.
	Args []string

	// ExitCode is the process exit status, or -1 when the command could not be
	// started or was terminated by a signal.
	ExitCode int

	// Stderr is the command's standard error, trimmed and capped.
	Stderr string

	// Err is the underlying error from the exec package, if any.
	Err error
}

func (e *CommandError) Error() string {
	var b strings.Builder
	b.WriteString(e.Cmd)
	for _, a := range e.Args {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	if e.ExitCode >= 0 {
		fmt.Fprintf(&b, ": exit status %d", e.ExitCode)
	} else if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.Stderr != "" {
		fmt.Fprintf(&b, ": %s", e.Stderr)
	}
	return b.String()
}

func (e *CommandError) Unwrap() error { return e.Err }

// exitCode returns the exit status carried by err, and whether err was a
// *CommandError at all. A command that never ran reports -1.
func exitCode(err error) (int, bool) {
	var ce *CommandError
	if errors.As(err, &ce) {
		return ce.ExitCode, true
	}
	return 0, false
}

// maxStderr caps the standard error retained in a CommandError. Enough to carry
// a drbdadm diagnostic, little enough that a tool spewing output cannot turn an
// error value into a memory problem.
const maxStderr = 4096

// allowedBinaries is every program this package will exec.
//
// Taking the binary name as a parameter is what makes the runner a seam a test
// can substitute, and also what makes it, read on its own, an arbitrary
// subprocess launcher. It is not one: the name is checked against this set
// before the exec, so a bug that let a caller-controlled string reach Run
// could not turn it into a way to run something else. Arguments are separate
// argv elements and never touch a shell.
//
// The mkfs entries are spelled out because the caller builds that name from a
// filesystem type. That type is already allowlisted in validate.go; this is the
// second lock on the same door, and the one that holds if the first is ever
// widened without thinking about what the name is used for.
var allowedBinaries = map[string]struct{}{
	binDRBDAdm:   {},
	binDRBDSetup: {},
	binLVCreate:  {},
	binLVRemove:  {},
	binLVExtend:  {},
	binLVS:       {},
	binLVChange:  {},
	binBlkid:     {},
	binResize2fs: {},
	binXFSGrowfs: {},
	binE2fsck:    {},
	"mkfs.ext4":  {},
	"mkfs.xfs":   {},
}

// execRunner is the production CommandRunner: it execs the binary with the
// given argv and no shell.
type execRunner struct {
	// allow replaces the binary allowlist. It exists so the tests for this
	// file can drive a real process without adding /bin/sh to what the
	// provider may run; nil, which is what New builds, means allowedBinaries.
	allow map[string]struct{}
}

// Run implements CommandRunner.
//
// The command inherits the process environment with LC_ALL and LANG forced to
// C, matching the local provider's runner. lvs output is parsed here, and its
// numeric fields are read as fixed ASCII: a localized build formats
// data_percent with the locale's decimal separator, and "12,34" reads through
// strconv.ParseFloat as zero rather than as an error, so every snapshot on such
// a host would silently report as occupying nothing. The byte counts are
// integers and would survive, which is exactly why this is worth pinning rather
// than detecting downstream — the failure is partial and quiet.
func (r execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	allow := r.allow
	if allow == nil {
		allow = allowedBinaries
	}
	if _, ok := allow[name]; !ok {
		return nil, &CommandError{
			Cmd: name, Args: args, ExitCode: -1,
			Err: fmt.Errorf("%w: %q is not a program this provider runs", common.ErrInvalidArgument, name),
		}
	}

	// #nosec G204 -- name is checked against allowedBinaries immediately above,
	// and args are separate argv elements handed to exec, never a shell.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}

	ce := &CommandError{
		Cmd:      name,
		Args:     args,
		ExitCode: -1,
		Stderr:   trimStderr(stderr.String()),
		Err:      err,
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		ce.ExitCode = ee.ExitCode()
	}
	// A context that is already done is the more useful diagnosis than the
	// "signal: killed" the kill produces, so surface it.
	if ctxErr := ctx.Err(); ctxErr != nil {
		ce.Err = ctxErr
	}
	return stdout.Bytes(), ce
}

func trimStderr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxStderr {
		return s[:maxStderr] + "…(truncated)"
	}
	return s
}
