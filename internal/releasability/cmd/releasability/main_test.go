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

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/releasability"
)

// newRepo creates a git repository holding files, all added to the index.
func newRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("git", "-C", root, "add", "-A").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	return root
}

func TestRunCleanTree(t *testing.T) {
	root := newRepo(t, map[string]string{"README.md": "hello 192.0.2.1\n"})
	var out, errOut bytes.Buffer
	if code := run(&out, &errOut, root); code != exitClean {
		t.Fatalf("run = %d, want %d\n%s%s", code, exitClean, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "examined 1 tracked file(s)") {
		t.Errorf("a passing run must say what it examined: %q", out.String())
	}
}

// TestRunFailsOnAPlantedLabAddress is the proof the ruling asks for: plant a
// lab address and the gate exits non-zero, naming it.
func TestRunFailsOnAPlantedLabAddress(t *testing.T) {
	planted := "10.1." + "2.3"
	root := newRepo(t, map[string]string{"README.md": "dial " + planted + "\n"})
	var out, errOut bytes.Buffer
	if code := run(&out, &errOut, root); code != exitFindings {
		t.Fatalf("run = %d, want %d\n%s%s", code, exitFindings, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), `README.md:1: [lab-address] "`+planted+`"`) {
		t.Errorf("report does not locate the planted address:\n%s", out.String())
	}
}

func TestRunOutsideARepository(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(&out, &errOut, t.TempDir()); code != exitCannotScan {
		t.Fatalf("run = %d, want %d", code, exitCannotScan)
	}
	if errOut.Len() == 0 {
		t.Error("a scan that could not run said nothing")
	}
}

func TestRunWithAnUntrustworthyExemptionList(t *testing.T) {
	root := newRepo(t, map[string]string{"a.txt": "x\n", releasability.ExemptFile: "a.txt\n"})
	var out, errOut bytes.Buffer
	if code := run(&out, &errOut, root); code != exitCannotScan {
		t.Fatalf("run = %d, want %d", code, exitCannotScan)
	}
	if !strings.Contains(errOut.String(), "states no reason") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunWhenTheReportCannotBeWritten(t *testing.T) {
	root := newRepo(t, map[string]string{"README.md": "hello\n"})
	var errOut bytes.Buffer
	if code := run(failingWriter{}, &errOut, root); code != exitCannotScan {
		t.Fatalf("run = %d, want %d", code, exitCannotScan)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }
