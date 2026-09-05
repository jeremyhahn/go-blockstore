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
	"errors"
	"strings"
	"testing"
)

// scannerReturning builds a scanner with a fixed answer, so the report can be
// driven through every branch without a tree to arrange.
func scannerReturning(name string, result Result, err error) Scanner {
	return Scanner{
		Name: name,
		What: "a scanner used to drive the report through one of its branches",
		Scan: func(string) (Result, error) { return result, err },
	}
}

// TestReportRefusesAnEmptyScannerSet is the requirement stated in #47 in its own
// words: an empty guard set must not read as success.
//
// Zero scanners produce zero findings and would otherwise exit 0 — which is
// character-for-character what a clean tree produces. The sweep that opened the
// issue printed exactly that, and it meant "there are no guards".
func TestReportRefusesAnEmptyScannerSet(t *testing.T) {
	var out strings.Builder

	err := Report(&out, t.TempDir(), nil)
	if !errors.Is(err, ErrNoScanners) {
		t.Fatalf("Report over an empty scanner set = %v, want ErrNoScanners", err)
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("the output of an empty sweep does not say FAIL, so it reads as a pass: %q", out.String())
	}
}

// TestReportSaysWhatItExaminedOnAPassingRun is the evidence half at the level a
// human reads. A clean run whose output is only "OK" is indistinguishable from a
// clean run over nothing.
func TestReportSaysWhatItExaminedOnAPassingRun(t *testing.T) {
	clean := scannerReturning("clean-one", Result{Examined: []string{"a.go", "b.go"}}, nil)

	var out strings.Builder
	if err := Report(&out, t.TempDir(), []Scanner{clean}); err != nil {
		t.Fatalf("Report over a clean scanner = %v, want nil", err)
	}

	text := out.String()
	for _, want := range []string{"clean-one", "examined 2 file(s)", "clean", "OK"} {
		if !strings.Contains(text, want) {
			t.Errorf("a passing report does not mention %q, so it carries no evidence it ran: %q", want, text)
		}
	}
}

// TestReportFailsAndLocatesEveryFinding covers the dirty path: the exit status,
// the file:line rendering and the rule restated next to it.
func TestReportFailsAndLocatesEveryFinding(t *testing.T) {
	dirty := scannerReturning("dirty-one", Result{
		Examined: []string{"x.sh"},
		Findings: []Finding{{File: "x.sh", Line: 7, Message: "swallowed the exit status"}},
	}, nil)

	var out strings.Builder
	err := Report(&out, t.TempDir(), []Scanner{dirty})
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("Report over a dirty tree = %v, want ErrFindings", err)
	}

	text := out.String()
	for _, want := range []string{"x.sh:7: swallowed the exit status", "1 finding(s)", "a scanner used to drive the report"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report is missing %q: %q", want, text)
		}
	}
}

// TestReportSeparatesADirtyTreeFromABrokenScan keeps the two apart at the point
// a caller acts on them. Both exit non-zero; only one means the tree is wrong.
func TestReportSeparatesADirtyTreeFromABrokenScan(t *testing.T) {
	t.Run("a scanner that examined nothing", func(t *testing.T) {
		var out strings.Builder
		err := Report(&out, t.TempDir(), []Scanner{scannerReturning("blind", Result{}, nil)})

		if !errors.Is(err, ErrScanFoundNothingToExamine) {
			t.Fatalf("Report over a blind scanner = %v, want ErrScanFoundNothingToExamine", err)
		}
		if errors.Is(err, ErrFindings) {
			t.Error("a scan that never ran was reported as a dirty tree")
		}
		if !strings.Contains(out.String(), "did not run") {
			t.Errorf("the output does not say the scan failed to run: %q", out.String())
		}
	})

	t.Run("a scanner that errored", func(t *testing.T) {
		sentinel := errors.New("the tree could not be walked")
		var out strings.Builder
		err := Report(&out, t.TempDir(), []Scanner{scannerReturning("broken", Result{}, sentinel)})

		if !errors.Is(err, sentinel) {
			t.Fatalf("Report over a failing scanner = %v, want the underlying error", err)
		}
		if errors.Is(err, ErrFindings) {
			t.Error("a failed scan was reported as a dirty tree")
		}
	})
}

// TestReportOverTheRealScannersIsTheGate is the binary's own path, run against
// this repository — the same call `make guards` makes.
//
// It duplicates TestGuardsTheRepositoryIsClean on purpose, through the OTHER
// entry point. The two exist because a gate reachable from the test binary and
// not from the command line is a gate that runs in one of the two places it is
// supposed to.
func TestReportOverTheRealScannersIsTheGate(t *testing.T) {
	var out strings.Builder
	if err := Report(&out, repoRoot(t), All()); err != nil {
		t.Fatalf("the repository does not pass its own guards:\n%s\n%v", out.String(), err)
	}
	t.Logf("%s", out.String())
}
