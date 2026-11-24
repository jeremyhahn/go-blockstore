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

// CommandRunner executes an external command with pre-split argv and no shell; implementations must not retain stdin, and a non-zero exit returns *ExitError.
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

	// Stdout is the command's trimmed standard output; some tools such as resize2fs report the reason there.
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

// Run executes name with args, feeding stdin when non-nil, with LC_ALL and LANG set to C.
func (execRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name and args are not caller-controlled, and there is no shell.
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

// runCommand writes stdin directly to the pipe, avoiding os/exec's unwiped copy buffer.
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

	// Always Wait; its error carries the exit status and is reported first.
	waitErr := cmd.Wait()
	if waitErr != nil {
		return waitErr
	}
	return errors.Join(writeErr, closeErr)
}
