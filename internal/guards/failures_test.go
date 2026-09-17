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

package guards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The paths in this file are the ones that decide whether a BROKEN scan reports
// as a clean one. They are the point of the package, and they are also the
// paths no ordinary run exercises, so they are driven here against trees this
// test builds and owns.

// TestAScanThatCannotReadIsNotAScanThatPassed covers every scanner against a
// file it cannot read.
//
// A scanner that swallowed the error would report zero findings for that file
// and the sweep would go green over material nobody looked at — the exact shape
// of the `|| true` bug one of these scanners exists to find.
//
// The unreadable file is a DANGLING SYMLINK rather than a mode-0000 file, and
// that is the whole reason this test is worth anything. Mode 0000 does not stop
// uid 0, so the first version returned early under root and asserted nothing —
// and `make test-container`, where this suite runs in CI, runs as root. It
// would have been a skip wearing a uid check, in the package whose subject is
// tests that report success without running. A dangling link fails the read for
// every uid.
func TestAScanThatCannotReadIsNotAScanThatPassed(t *testing.T) {
	cases := map[string]struct {
		name    string
		scanner Scanner
	}{
		"no-runtime-skip":              {"unreadable.go", SkipGuards()},
		"no-unexplained-fail-open":     {"unreadable.sh", FailOpenShell()},
		"privileged-is-never-a-remedy": {"unreadable.md", PrivilegedAsRemedy()},
		"key-material-custody":         {"unreadable.go", KeyMaterialCustody()},
	}

	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, tc.name)
			if err := os.Symlink(filepath.Join(root, "nothing-is-here"), path); err != nil {
				t.Fatalf("Symlink: %v", err)
			}

			if _, err := tc.scanner.Scan(root); err == nil {
				t.Fatalf("%s reported success over a file it could not read; a scan that could not run is not a scan that passed", label)
			}
		})
	}
}

// TestAnUnparseableGoFileIsAScanFailure keeps the skip scanner from failing open
// on the file most likely to be unusual.
//
// A parser error that quietly produced zero findings would be the scanner
// declining to look at exactly the file worth looking at.
func TestAnUnparseableGoFileIsAScanFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte("package ???\nfunc ("), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := SkipGuards().Scan(root); err == nil {
		t.Fatal("the skip scanner reported success over a file it could not parse")
	}
	if _, err := KeyMaterialCustody().Scan(root); err == nil {
		t.Fatal("the custody scanner reported success over a file it could not parse")
	}
}

// TestRunReportsEveryFailureRatherThanTheFirst keeps a caller from fixing one
// broken scanner at a time.
func TestRunReportsEveryFailureRatherThanTheFirst(t *testing.T) {
	blindOne := Scanner{Name: "a", What: "reads nothing", Scan: func(string) (Result, error) { return Result{}, nil }}
	blindTwo := Scanner{Name: "b", What: "reads nothing", Scan: func(string) (Result, error) { return Result{}, nil }}
	working := Scanner{
		Name: "c", What: "reads something",
		Scan: func(string) (Result, error) { return Result{Examined: []string{"x"}}, nil },
	}

	results, err := Run(t.TempDir(), []Scanner{blindOne, blindTwo, working})
	if err == nil {
		t.Fatal("Run over two blind scanners reported success")
	}
	for _, name := range []string{"a", "b"} {
		if _, present := results[name]; present {
			t.Errorf("blind scanner %q produced a result a caller could read as a pass", name)
		}
	}
	if _, present := results["c"]; !present {
		t.Error("a working scanner's result was dropped because another failed")
	}
	if got := err.Error(); !strings.Contains(got, "a:") || !strings.Contains(got, "b:") {
		t.Errorf("the joined error does not name both failures: %v", err)
	}
}

// TestWalkSurfacesAnUnreadableTree keeps the walk itself from failing open.
func TestWalkSurfacesAnUnreadableTree(t *testing.T) {
	if _, err := walk(filepath.Join(t.TempDir(), "does-not-exist"), func(string) bool { return true }); err == nil {
		t.Fatal("walking a tree that does not exist reported success")
	}
}

// TestScannersReportWhatTheyExaminedEvenWhenClean is the evidence half: a clean
// result must still say what it read, or it is indistinguishable from a scan
// that read nothing.
func TestScannersReportWhatTheyExaminedEvenWhenClean(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "clean.go"), []byte("package p\n\nfunc F() {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "clean.sh"), []byte("#!/bin/sh\necho hi\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "clean.md"), []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, scanner := range All() {
		t.Run(scanner.Name, func(t *testing.T) {
			result, err := scanner.Scan(root)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(result.Findings) != 0 {
				t.Errorf("fired on a clean tree: %v", result.Findings)
			}
			if len(result.Examined) == 0 {
				t.Error("reported a clean result without saying what it read, which is what a broken scanner also reports")
			}
		})
	}
}
