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

package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CommandRunner executes an external command. Every system tool this provider
// drives — lvm, mkfs, findmnt, blkid, dd — goes through this one interface, so
// tests exercise the whole provider against a fake and never need root, LVM or
// a block device.
//
// LUKS is NOT among them and has not been since 2026-08-29: formatting,
// unlocking and header reads happen in this process through luksBackend, which
// is a separate seam for a reason — there is no command to run.
//
// name is the binary and args are its arguments, already split: an
// implementation passes them as individual argv elements and must not hand the
// pair to a shell. Nothing the provider produces is quoted or escaped for shell
// consumption, so a runner that builds a command line out of them reintroduces
// exactly the injection the provider's validation exists to prevent.
//
// stdin, when non-nil, is written to the command's standard input. No command
// this provider runs uses it any more — the one that did was the cryptsetup
// that consumed a passphrase there — and it is kept because the interface is
// exported and callers implement it, and because a tool added later may need
// it.
//
// AN IMPLEMENTATION MUST NOT RETAIN stdin, or copy it anywhere that outlives
// the call. That rule stands whether or not the bytes are a secret today: the
// provider passes a slice it borrowed for exactly the length of one command,
// and a runner that keeps one has changed the caller's lifetime guarantees
// without saying so.
//
// Run returns the command's standard output. When the command starts and exits
// non-zero it returns *ExitError, which the provider distinguishes from a
// failure to start at all — several tools (blkid, findmnt) report "no such
// thing" as a non-zero exit, and treating a missing binary the same way would
// silently turn a broken host into an empty answer.
type CommandRunner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// ExitError reports a command that ran to completion and exited non-zero.
type ExitError struct {
	// Name is the binary that was executed.
	Name string

	// Args are the arguments it was executed with.
	Args []string

	// Code is the process exit status.
	Code int

	// Stderr is what the command wrote to standard error, trimmed.
	Stderr string

	// Stdout is what the command wrote to standard output, trimmed.
	//
	// It is carried because not every tool reports its reason on stderr:
	// resize2fs writes only its version banner there and puts the actual
	// diagnosis — "Please run e2fsck -f first", or what it did instead — on
	// stdout. An error built from stderr alone reads as a bare "exit status 1"
	// for exactly the failures somebody needs to act on.
	Stdout string
}

func (e *ExitError) Error() string {
	msg := fmt.Sprintf("%s %s: exit status %d", e.Name, strings.Join(e.Args, " "), e.Code)
	for _, out := range []string{e.Stderr, e.Stdout} {
		if out != "" {
			msg += ": " + out
		}
	}
	return msg
}

// asExitError reports whether err is (or wraps) an *ExitError, returning it.
func asExitError(err error) (*ExitError, bool) {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee, true
	}
	return nil, false
}

// execRunner is the default CommandRunner, backed by os/exec.
type execRunner struct{}

// Run executes name with args, feeding it stdin when non-nil.
//
// The command inherits the process environment with LC_ALL and LANG forced to
// C. lvs, blkid and findmnt output is parsed here, and a localized build
// otherwise translates the very field names and numeric formats the parser
// depends on.
func (execRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name and args are not caller-controlled, and there is no shell.
	//
	// G204 fires because the binary and its arguments are variables. They are
	// not variables an outside caller can set: execRunner is unexported, is
	// constructed only by New, and is never returned, so the only code that can
	// reach this line is this package's own provider methods. Every `name` they
	// pass is a string constant except the mkfs binary, which is read out of the
	// mkfsBinaries allowlist table rather than built by concatenating a
	// caller's FSType onto "mkfs." — deliberately, so that FSType can never
	// become a choice of which program runs.
	//
	// The arguments reach exec as separate argv elements with no shell in
	// between, so nothing in them is word-split or expanded, and each one has
	// been through the allowlist validation in validate.go before arriving.
	// Key material never appears here at all; it goes to the process on stdin.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := runCommand(cmd, stdin)
	if err := runErr; err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return stdout.Bytes(), &ExitError{
				Name:   name,
				Args:   append([]string(nil), args...),
				Code:   ee.ExitCode(),
				Stderr: strings.TrimSpace(stderr.String()),
				Stdout: strings.TrimSpace(stdout.String()),
			}
		}
		return stdout.Bytes(), fmt.Errorf("go-blockstore/local: running %s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

// runCommand runs cmd, feeding it stdin when there is any.
//
// The bytes are written to the process's stdin pipe directly rather than handed
// to exec as an io.Reader. Setting cmd.Stdin to a reader makes os/exec copy
// through a 32 KiB heap buffer of its own, and that buffer is an unprotected,
// unwiped copy of whatever passed through it — for this package, a LUKS
// passphrase borrowed out of locked memory. Writing to the pipe puts the bytes
// on the fd straight from the pages they were borrowed from.
func runCommand(cmd *exec.Cmd, stdin []byte) error {
	if stdin == nil {
		return cmd.Run()
	}

	pipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("go-blockstore/local: opening stdin for %s: %w", cmd.Path, err)
	}
	if err := cmd.Start(); err != nil {
		_ = pipe.Close()
		return err
	}

	_, writeErr := pipe.Write(stdin)
	closeErr := pipe.Close()

	// Wait runs whatever happened above: the process is already running, and
	// skipping Wait would leak it along with its file descriptors. Its error is
	// the one that carries the exit status, so it is reported first when the
	// command itself failed.
	waitErr := cmd.Wait()
	if waitErr != nil {
		return waitErr
	}
	return errors.Join(writeErr, closeErr)
}
