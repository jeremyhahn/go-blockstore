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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/guards"
)

// TestRunOverThisRepositoryIsClean runs the gate as make guards does and checks the examined counts are printed.
func TestRunOverThisRepositoryIsClean(t *testing.T) {
	var out, errOut strings.Builder

	if code := run(&out, &errOut, ".", guards.All()); code != exitClean {
		t.Fatalf("run over this repository = %d, want %d\nstdout:\n%s\nstderr:\n%s",
			code, exitClean, out.String(), errOut.String())
	}

	text := out.String()
	if !strings.Contains(text, "examined") {
		t.Errorf("a passing run does not say what it examined, so it is indistinguishable from one that read nothing: %q", text)
	}
	if !strings.Contains(text, "OK:") {
		t.Errorf("a passing run does not say OK: %q", text)
	}
	t.Logf("%s", text)
}

// TestRunReportsAnUnscannableTree: exit 2 means the tree could not be scanned, exit 1 means it is dirty.
func TestRunReportsAnUnscannableTree(t *testing.T) {
	// t.TempDir() is under the system temp directory, which has no go.mod at or
	// above it — unless the temp directory is inside a module, so this asserts
	// the premise rather than assuming it.
	dir := t.TempDir()
	for at := dir; ; {
		if _, err := os.Stat(filepath.Join(at, "go.mod")); err == nil {
			t.Fatalf("%s is inside a Go module, so this test cannot arrange an unscannable tree", dir)
		}
		parent := filepath.Dir(at)
		if parent == at {
			break
		}
		at = parent
	}

	var out, errOut strings.Builder
	if code := run(&out, &errOut, dir, guards.All()); code != exitCannotScan {
		t.Fatalf("run over a directory with no module above it = %d, want %d", code, exitCannotScan)
	}
	if !strings.Contains(errOut.String(), "no go.mod") {
		t.Errorf("the error does not say what was missing: %q", errOut.String())
	}
}

// TestRunExitsNonZeroOnADirtyTree plants a finding through the scanner list, leaving the tree untouched.
func TestRunExitsNonZeroOnADirtyTree(t *testing.T) {
	alwaysFires := guards.Scanner{
		Name: "always-fires",
		What: "a scanner that reports one finding, to reach the dirty exit status",
		Scan: func(string) (guards.Result, error) {
			return guards.Result{
				Examined: []string{"planted.go"},
				Findings: []guards.Finding{{File: "planted.go", Line: 1, Message: "a planted violation"}},
			}, nil
		},
	}

	var out, errOut strings.Builder
	if code := run(&out, &errOut, ".", []guards.Scanner{alwaysFires}); code != exitFindings {
		t.Fatalf("run over a dirty tree = %d, want %d\n%s", code, exitFindings, out.String())
	}
	if !strings.Contains(out.String(), "planted.go:1: a planted violation") {
		t.Errorf("the finding is not located in the output: %q", out.String())
	}
}

// TestRunRefusesAnEmptyScannerSet is #47's other stated requirement at the
// command line: an empty guard set exits non-zero rather than reading as a
// clean sweep.
func TestRunRefusesAnEmptyScannerSet(t *testing.T) {
	var out, errOut strings.Builder
	if code := run(&out, &errOut, ".", nil); code != exitFindings {
		t.Fatalf("run with no scanners = %d, want a non-zero %d", code, exitFindings)
	}
	if !strings.Contains(out.String(), "no scanners") {
		t.Errorf("the output does not say the sweep had nothing to run: %q", out.String())
	}
}

// TestExitStatusesAreDistinct pins the three apart. They are separate constants
// precisely so a caller can tell "the tree is dirty" from "the scan did not
// happen", and two of them colliding would silently remove that distinction.
func TestExitStatusesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"exitClean":      exitClean,
		"exitFindings":   exitFindings,
		"exitCannotScan": exitCannotScan,
	} {
		if other, clash := seen[code]; clash {
			t.Errorf("%s and %s are both %d, so the two outcomes are indistinguishable to a caller", name, other, code)
		}
		seen[code] = name
	}
	if exitClean != 0 {
		t.Errorf("exitClean = %d, want 0: a shell reads any other value as a failure", exitClean)
	}
}
