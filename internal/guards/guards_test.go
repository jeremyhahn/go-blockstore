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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot locates the repository being scanned.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := Root(".")
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return root
}

// fixture returns the path to one of this package's control trees.
func fixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(GuardFixtureDir), name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the %s fixture is missing: %v — without it no scanner can be shown to fire", name, err)
	}
	return path
}

// plantedViolations is the golden set: every violation the dirty fixture tree
// contains, per scanner, located exactly.
//
// # Why exact locations and not "it found something"
//
// The first version of the test below asserted only len(Findings) > 0, and
// mutation testing on 2026-09-04 killed it: deleting "Skip" from skipMethods,
// and deleting "|| true" from failOpenPatterns, each left it GREEN. The
// fixtures hold several violations apiece, so a scanner that lost the ability
// to see one of them still fired on the rest and the count stayed non-zero.
//
// A positive control that any surviving detection satisfies is not a positive
// control for the detection you removed. So the fixtures now carry one
// violation per recognized SPELLING — each receiver, each method, each
// exit-swallow form, each file type — and the assertion is set equality:
// nothing missing, and nothing extra either, because a scanner that started
// firing on a line the fixture calls clean is the false-positive failure that
// gets a guard switched off.
var plantedViolations = map[string][]Finding{
	"no-runtime-skip": {
		{File: "skip_fixture.go", Line: 21}, // t.Skip
		{File: "skip_fixture.go", Line: 26}, // t.Skipf
		{File: "skip_fixture.go", Line: 30}, // t.SkipNow
		{File: "skip_fixture.go", Line: 34}, // testing.Short()
		{File: "skip_fixture.go", Line: 40}, // b.Skip
		{File: "skip_fixture.go", Line: 44}, // f.Skip
		{File: "skip_fixture.go", Line: 48}, // tb.Skip
	},
	"no-unexplained-fail-open": {
		{File: "Makefile", Line: 5},   // a Makefile recipe, not only .sh
		{File: "deploy.yml", Line: 7}, // a CI workflow step
		{File: "run.sh", Line: 8},     // || true
		{File: "run.sh", Line: 10},    // ||true
		{File: "run.sh", Line: 12},    // || :
		{File: "run.sh", Line: 14},    // ||:
		{File: "run.sh", Line: 17},    // a trailing comment stating no reason
	},
	"privileged-is-never-a-remedy": {
		{File: "DEPLOY.md", Line: 3},  // prose offering the flag
		{File: "DEPLOY.md", Line: 6},  // a second phrasing
		{File: "deploy.yml", Line: 6}, // a workflow step passing it
	},
	"key-material-custody": {
		// Rule 1: the two copying exits from the enclave.
		{File: "pkg/other/custody_fixture.go", Line: 27}, // enc.Open()
		{File: "pkg/other/custody_fixture.go", Line: 31}, // enc.OpenString()
		// Rule 2: a borrow outside the window — in another package, and in
		// internal/luks itself but not in withKey.
		{File: "pkg/other/custody_fixture.go", Line: 37}, // enc.WithBytes from pkg/other
		{File: "internal/luks/manager.go", Line: 39},     // enc.WithBytes from (*Manager).peek
		// Rule 3: each key-taking Backend method, called from outside internal/luks.
		{File: "pkg/other/custody_fixture.go", Line: 43}, // b.Format
		{File: "pkg/other/custody_fixture.go", Line: 46}, // b.Open
		{File: "pkg/other/custody_fixture.go", Line: 49}, // b.TestKey
		// Rule 4: each position a borrowed key may not appear in.
		{File: "pkg/other/custody_fixture.go", Line: 58}, // k := key
		{File: "pkg/other/custody_fixture.go", Line: 63}, // holder{k: key} not passed to a call
		{File: "pkg/other/custody_fixture.go", Line: 68}, // append(dst, key...)
		{File: "pkg/other/custody_fixture.go", Line: 72}, // copy(dst, key)
		{File: "pkg/other/custody_fixture.go", Line: 76}, // string(key)
		{File: "pkg/other/custody_fixture.go", Line: 80}, // captured by a closure that is returned
		{File: "pkg/other/custody_fixture.go", Line: 84}, // key[:4]
		{File: "pkg/other/custody_fixture.go", Line: 88}, // p := passphrase
		// Rule 5: each shape of an exported clear-text seam.
		{File: "pkg/other/custody_fixture.go", Line: 95},  // key []byte parameter
		{File: "pkg/other/custody_fixture.go", Line: 97},  // luksKey string: a qualified key is material even as a string
		{File: "pkg/other/custody_fixture.go", Line: 99},  // passphrase []byte parameter
		{File: "pkg/other/custody_fixture.go", Line: 101}, // secret
		{File: "pkg/other/custody_fixture.go", Line: 103}, // password
		{File: "pkg/other/custody_fixture.go", Line: 105}, // token
		{File: "pkg/other/custody_fixture.go", Line: 107}, // a named result, rootPassword
		{File: "pkg/other/custody_fixture.go", Line: 109}, // luksKeyBytes, the material-then-bytes shape
		{File: "pkg/other/custody_fixture.go", Line: 112}, // an exported interface's method
		{File: "pkg/other/custody_fixture.go", Line: 117}, // an exported method
		{File: "pkg/other/custody_fixture.go", Line: 119}, // an exported func type
	},
}

// TestGuardsEveryScannerCanSayYes is THE binding requirement, applied to every
// scanner uniformly.
//
// A scanner that has never fired is a scanner nobody knows is wired up, and its
// silence over the repository means nothing. Each one is therefore run against
// a fixture tree that DOES contain the violation it looks for, and required to
// report every planted instance — see plantedViolations for why "every" rather
// than "at least one".
//
// It iterates All(), so a scanner added to the command line without a fixture
// fails here rather than shipping unverified.
func TestGuardsEveryScannerCanSayYes(t *testing.T) {
	dirty := fixture(t, "dirty")

	for _, scanner := range All() {
		t.Run(scanner.Name, func(t *testing.T) {
			want, planted := plantedViolations[scanner.Name]
			if !planted {
				t.Fatalf("%s has no planted violations, so nothing here proves it can fire. "+
					"Add its violation to internal/guards/testdata/dirty and list it in plantedViolations.",
					scanner.Name)
			}

			result, err := scanner.Scan(dirty)
			if err != nil {
				t.Fatalf("scanning the dirty fixture: %v", err)
			}
			if len(result.Examined) == 0 {
				t.Fatalf("%s examined no files in the dirty fixture, so it cannot have found anything", scanner.Name)
			}
			if len(result.Findings) == 0 {
				t.Fatalf("%s found nothing in a tree planted with its own violation — it has never fired, "+
					"so its silence over the repository is not evidence of anything (examined %d files: %v)",
					scanner.Name, len(result.Examined), result.Examined)
			}

			got := map[string]bool{}
			for _, finding := range result.Findings {
				got[fmt.Sprintf("%s:%d", finding.File, finding.Line)] = true

				if finding.File == "" || finding.Line <= 0 {
					t.Errorf("finding is not locatable: %+v", finding)
				}
				if len(finding.Message) < 40 {
					t.Errorf("finding %s carries no actionable message: %q", finding.File, finding.Message)
				}
			}

			for _, expected := range want {
				at := fmt.Sprintf("%s:%d", expected.File, expected.Line)
				if !got[at] {
					t.Errorf("%s did not report the violation planted at %s. Every planted violation is a "+
						"separate spelling of the rule, so a miss here is a spelling this scanner can no longer see "+
						"— found instead: %v", scanner.Name, at, result.Findings)
				}
				delete(got, at)
			}
			for at := range got {
				t.Errorf("%s fired at %s, which the dirty fixture does not plant. A scanner reporting lines "+
					"nobody wrote a violation on is the false positive that gets a guard switched off.",
					scanner.Name, at)
			}
		})
	}
}

// TestEveryScannerHasPlantedViolations keeps the golden table and All() in step
// from the other direction: a stale entry for a scanner that was renamed or
// removed would sit there looking like coverage of something.
func TestEveryScannerHasPlantedViolations(t *testing.T) {
	live := map[string]bool{}
	for _, scanner := range All() {
		live[scanner.Name] = true
	}
	for name := range plantedViolations {
		if !live[name] {
			t.Errorf("plantedViolations names %q, which All() does not return — the entry proves nothing", name)
		}
	}
	if len(plantedViolations) == 0 {
		t.Fatal("no scanner has a planted violation, so no scanner has been shown to fire")
	}
}

// TestGuardsEveryScannerIsSilentOnCleanCode is the other half. A scanner that
// refuses everything passes the test above and is worse than none, because the
// only way to ship work past it is to switch it off.
//
// The clean fixture is deliberately adversarial: it contains prose ABOUT each
// violation, the constructions inside string literals, and the near-misses that
// a textual scanner would report — t.Parallel, a decoder's Skip method, a
// comment discussing `|| true`, and a properly phrased --privileged warning.
func TestGuardsEveryScannerIsSilentOnCleanCode(t *testing.T) {
	clean := fixture(t, "clean")

	for _, scanner := range All() {
		t.Run(scanner.Name, func(t *testing.T) {
			result, err := scanner.Scan(clean)
			if err != nil {
				t.Fatalf("scanning the clean fixture: %v", err)
			}
			if len(result.Examined) == 0 {
				t.Fatalf("%s examined no files in the clean fixture, so its silence proves nothing", scanner.Name)
			}
			for _, finding := range result.Findings {
				t.Errorf("%s fired on code that does not violate it, which is how a guard gets switched off: %s",
					scanner.Name, finding)
			}
		})
	}
}

// TestGuardsTheRepositoryIsClean is the scan that actually gates the build.
//
// It asserts the finding count AND the examined count, because those are
// different claims: zero findings over zero files is what a broken scanner
// reports, and it is indistinguishable from a clean tree unless the second
// number is checked. That indistinguishability is the whole reason this package
// exists.
func TestGuardsTheRepositoryIsClean(t *testing.T) {
	root := repoRoot(t)

	results, err := Run(root, All())
	if err != nil {
		t.Fatalf("the scan itself failed, which is not the same as passing: %v", err)
	}

	for _, scanner := range All() {
		result, ran := results[scanner.Name]
		if !ran {
			t.Errorf("%s produced no result at all", scanner.Name)
			continue
		}
		if len(result.Examined) == 0 {
			t.Errorf("%s examined no files", scanner.Name)
			continue
		}
		t.Logf("%s examined %d files", scanner.Name, len(result.Examined))
		for _, finding := range result.Findings {
			t.Errorf("[%s] %s\n    (%s)", scanner.Name, finding, scanner.What)
		}
	}
}

// TestGuardsRunRejectsAScannerThatExaminedNothing is the fail-closed rule at the
// point it is enforced. An empty file list must never be reported as a pass.
func TestGuardsRunRejectsAScannerThatExaminedNothing(t *testing.T) {
	blind := Scanner{
		Name: "blind",
		What: "a scanner that reads nothing",
		Scan: func(string) (Result, error) { return Result{}, nil },
	}

	_, err := Run(repoRoot(t), []Scanner{blind})
	if !errors.Is(err, ErrScanFoundNothingToExamine) {
		t.Fatalf("Run over a scanner that examined nothing = %v, want ErrScanFoundNothingToExamine", err)
	}
}

// TestGuardsRunSurfacesAScanFailure keeps a broken scan from reading as a clean
// one — the same rule one level up.
func TestGuardsRunSurfacesAScanFailure(t *testing.T) {
	sentinel := errors.New("the scan could not run")
	broken := Scanner{
		Name: "broken",
		What: "a scanner that fails",
		Scan: func(string) (Result, error) { return Result{}, sentinel },
	}

	results, err := Run(repoRoot(t), []Scanner{broken})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run over a failing scanner = %v, want the underlying error", err)
	}
	if _, present := results["broken"]; present {
		t.Error("a failed scan produced a result, which a caller could read as a pass")
	}
}

// TestGuardsSkipTheirOwnFixtures pins the exclusion that keeps the repository
// sweep green.
//
// The fixtures hold deliberate violations. If the sweep descended into them,
// every scanner would report them forever and the suite would be permanently
// red — the shape that gets a guard deleted.
//
// It also pins the NARROWNESS of the exclusion: only this package's fixture
// root is skipped, by exact path. A blanket "skip anything called testdata"
// would be the scanner blinding itself, which is the failure this package is
// about.
func TestGuardsSkipTheirOwnFixtures(t *testing.T) {
	root := repoRoot(t)

	files, err := walk(root, func(rel string) bool { return true })
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("the walk found no files at all")
	}

	for _, rel := range files {
		if strings.HasPrefix(rel, GuardFixtureDir+"/") {
			t.Errorf("the sweep descended into this package's own fixtures: %s", rel)
		}
	}

	// And the exclusion must not be a blanket one. Another package's testdata
	// is real material and has to stay in scope.
	other := filepath.Join(root, "pkg", "drbd", "testdata")
	if _, err := os.Stat(other); err == nil {
		var sawOther bool
		for _, rel := range files {
			if strings.HasPrefix(rel, "pkg/drbd/testdata/") {
				sawOther = true
				break
			}
		}
		if !sawOther {
			t.Error("pkg/drbd/testdata was excluded; only internal/guards' own fixtures may be")
		}
	}
}

// TestGuardsWalkSkipsTheDirectoriesItShould keeps the sweep off material that
// is not this repository's to judge.
func TestGuardsWalkSkipsTheDirectoriesItShould(t *testing.T) {
	root := t.TempDir()

	for _, dir := range []string{".git", "coverage", "vendor", ".deps", "pkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "f.go"), []byte("package p\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	files, err := walk(root, func(rel string) bool { return hasExt(rel, ".go") })
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	want := map[string]bool{"pkg/f.go": true}
	for _, rel := range files {
		if !want[rel] {
			t.Errorf("walk descended into %s", rel)
		}
		delete(want, rel)
	}
	for rel := range want {
		t.Errorf("walk missed %s, which it should read", rel)
	}
}

// TestGuardsEveryScannerIsNamedAndDescribed keeps a finding actionable at the
// banner level: a scanner whose failure says only "no-runtime-skip" leaves an
// engineer to guess the rule.
func TestGuardsEveryScannerIsNamedAndDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, scanner := range All() {
		if scanner.Name == "" {
			t.Error("a scanner has no name")
		}
		if seen[scanner.Name] {
			t.Errorf("two scanners are called %q; Run keys results by name and one would be lost", scanner.Name)
		}
		seen[scanner.Name] = true

		if len(scanner.What) < 30 {
			t.Errorf("%s does not describe its rule: %q", scanner.Name, scanner.What)
		}
		if scanner.Scan == nil {
			t.Errorf("%s has no Scan function", scanner.Name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("All() is empty, so make guards would pass by checking nothing")
	}
}

// TestFindingStringIsClickable keeps the output in the file:line:message shape
// an editor and a human both read.
func TestFindingStringIsClickable(t *testing.T) {
	got := Finding{File: "pkg/local/x.go", Line: 42, Message: "something"}.String()
	if want := "pkg/local/x.go:42: something"; got != want {
		t.Errorf("Finding.String() = %q, want %q", got, want)
	}
}

// TestRootWalksUpToGoMod covers both outcomes of the root search.
func TestRootWalksUpToGoMod(t *testing.T) {
	t.Run("found from a nested directory", func(t *testing.T) {
		root, err := Root("../..")
		if err != nil {
			t.Fatalf("Root: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
			t.Errorf("Root returned %s, which has no go.mod", root)
		}
	})

	t.Run("absent above the starting point", func(t *testing.T) {
		// A temporary directory is not inside the module, so the walk reaches
		// the filesystem root without finding go.mod.
		if _, err := Root(t.TempDir()); err == nil {
			t.Error("Root succeeded from a directory with no module above it")
		}
	})
}
