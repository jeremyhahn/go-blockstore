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
	"context"
	"errors"
	"strings"
	"testing"
)

// TestExecRunnerPassesArgvUnsplit is the property the whole validation scheme
// rests on: an argument containing shell metacharacters reaches the program as
// one argument, because there is no shell between here and there.
func TestExecRunnerPassesArgvUnsplit(t *testing.T) {
	const hostile = "a; rm -rf / && echo $HOME `id`"

	out, err := execRunner{}.Run(context.Background(), nil, "printf", "%s", hostile)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != hostile {
		t.Fatalf("printf received %q, want the single argument %q", out, hostile)
	}
}

func TestExecRunnerFeedsStdin(t *testing.T) {
	out, err := execRunner{}.Run(context.Background(), []byte("passphrase"), "cat")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != "passphrase" {
		t.Fatalf("cat echoed %q, want the stdin bytes", out)
	}
}

func TestExecRunnerReportsExitStatus(t *testing.T) {
	_, err := execRunner{}.Run(context.Background(), nil, "sh", "-c", "echo trouble >&2; exit 3")

	exitErr, ok := asExitError(err)
	if !ok {
		t.Fatalf("Run = %v, want an *ExitError", err)
	}
	if exitErr.Code != 3 {
		t.Errorf("Code = %d, want 3", exitErr.Code)
	}
	if exitErr.Stderr != "trouble" {
		t.Errorf("Stderr = %q, want %q", exitErr.Stderr, "trouble")
	}
	if !strings.Contains(exitErr.Error(), "exit status 3") || !strings.Contains(exitErr.Error(), "trouble") {
		t.Errorf("Error() = %q, want the status and the stderr", exitErr.Error())
	}
}

// TestExecRunnerDistinguishesAMissingBinary is what lets probeFSType tell "no
// filesystem signature" from "blkid is not installed". A missing binary never
// ran, so it is not an *ExitError.
func TestExecRunnerDistinguishesAMissingBinary(t *testing.T) {
	_, err := execRunner{}.Run(context.Background(), nil, "go-blockstore-no-such-binary")
	if err == nil {
		t.Fatal("Run succeeded for a binary that does not exist")
	}
	if _, ok := asExitError(err); ok {
		t.Fatalf("a missing binary was reported as an *ExitError: %v", err)
	}
}

// TestExecRunnerForcesTheCLocale keeps a localized host from translating the
// lvs, blkid and findmnt output this package parses.
func TestExecRunnerForcesTheCLocale(t *testing.T) {
	out, err := execRunner{}.Run(context.Background(), nil, "sh", "-c", "printf '%s' \"$LC_ALL\"")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != "C" {
		t.Fatalf("LC_ALL = %q, want C", out)
	}
}

func TestExecRunnerHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := (execRunner{}).Run(ctx, nil, "sleep", "30"); err == nil {
		t.Fatal("Run succeeded under a canceled context")
	}
}

func TestAsExitErrorUnwraps(t *testing.T) {
	if _, ok := asExitError(nil); ok {
		t.Error("asExitError(nil) reported an *ExitError")
	}
	if _, ok := asExitError(errors.New("plain")); ok {
		t.Error("asExitError(plain error) reported an *ExitError")
	}

	wrapped := errors.Join(errors.New("context"), &ExitError{Name: "lvs", Code: 5})
	got, ok := asExitError(wrapped)
	if !ok {
		t.Fatal("asExitError did not find the wrapped *ExitError")
	}
	if got.Code != 5 {
		t.Errorf("Code = %d, want 5", got.Code)
	}
}

func TestExitErrorWithoutStderr(t *testing.T) {
	err := &ExitError{Name: "lvremove", Args: []string{"--force", "vg0/data"}, Code: 5}
	if got, want := err.Error(), "lvremove --force vg0/data: exit status 5"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
