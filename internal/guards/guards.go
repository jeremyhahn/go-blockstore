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

// Package guards holds the whole-tree scanners: the checks that assert a
// property across the ENTIRE repository rather than over whatever a test
// happens to touch.
//
// # Why a scanner has to prove it can say yes
//
// This package exists because a guard sweep over this repository printed
// nothing, and empty output from a guard loop is indistinguishable from "every
// guard passed". It was neither: there were no guards. The sweep was correct to
// be empty, and the only way to know that was to read what it had ENUMERATED.
//
// So every Scanner reports what it examined as well as what it found, and
// Result.Examined being empty is a failure rather than a clean run. An empty
// file list and a clean tree produce the same finding count; they must not
// produce the same verdict.
//
// The rule the tests enforce on every scanner here:
//
//  1. It fires on a fixture that DOES contain the violation. A scanner that has
//     never once fired is a scanner nobody knows is wired up.
//  2. It is silent on a fixture that does not.
//  3. It examined a non-empty set of files.
//
// A scanner that cannot satisfy (1) is not merged.
//
// # Why these scan text and AST rather than shelling out to grep
//
// Two reasons, both learned here. A `grep exec.Command("<literal>")` audit of
// this repository reported six binaries against a real count near twenty,
// because pkg/drbd names every binary in a constant — a scanner that matches
// literals cannot see what the real dispatch path produces. And a shell scanner
// is where `|| true` and `grep -c` defaulting to zero live, which is one of the
// things being scanned FOR.
//
// The skip scanner in particular parses Go rather than matching text, because a
// textual one fires on its own documentation: this very package names t.Skip in
// prose several times.
package guards

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one violation, located precisely enough to act on.
type Finding struct {
	// File is the path relative to the repository root.
	File string

	// Line is the 1-based line number.
	Line int

	// Message says what is wrong AND what to do about it. A finding an
	// engineer cannot act on gets suppressed rather than fixed.
	Message string
}

// String renders a finding the way an editor and a human both read.
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Message)
}

// Result is what a scanner saw as well as what it found.
//
// Examined is not diagnostics. It is the evidence that the scan happened at
// all, and the tests assert it is non-empty for exactly the reason in the
// package comment.
type Result struct {
	// Examined lists every file the scanner actually read, relative to the
	// repository root, sorted.
	Examined []string

	// Findings lists the violations, in the order the files were examined.
	Findings []Finding
}

// Scanner is one whole-tree check.
type Scanner struct {
	// Name identifies the scanner on the command line and in test output.
	Name string

	// What describes the property in one line, for the failure banner.
	What string

	// Scan reads the tree rooted at root and reports what it examined and what
	// it found. It returns an error only when the SCAN ITSELF failed —
	// unreadable directory, unparseable file — never for a violation. A scan
	// that could not run is not a scan that passed.
	Scan func(root string) (Result, error)
}

// All returns every scanner, in a stable order.
//
// It is a function rather than a package variable so that the test which
// asserts every scanner satisfies the positive-control rule iterates over the
// same list the command line runs. A scanner reachable from one and not the
// other is a scanner running unverified.
func All() []Scanner {
	return []Scanner{
		SkipGuards(),
		FailOpenShell(),
		PrivilegedAsRemedy(),
	}
}

// ErrScanFoundNothingToExamine reports a scanner that read no files.
//
// It is the fail-closed direction and the reason this package exists: a scanner
// whose file list came out empty reports the same zero findings as a clean
// tree, so the two are separated here rather than left to the reader.
var ErrScanFoundNothingToExamine = errors.New("guards: the scanner examined no files, so its silence means nothing")

// Run executes every scanner against root and returns the findings, keyed by
// scanner name.
//
// A scanner that examined nothing is an error, not an empty result.
func Run(root string, scanners []Scanner) (map[string]Result, error) {
	results := make(map[string]Result, len(scanners))
	var failures []error

	for _, scanner := range scanners {
		result, err := scanner.Scan(root)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", scanner.Name, err))
			continue
		}
		if len(result.Examined) == 0 {
			failures = append(failures, fmt.Errorf("%s: %w", scanner.Name, ErrScanFoundNothingToExamine))
			continue
		}
		results[scanner.Name] = result
	}
	return results, errors.Join(failures...)
}

// Root finds the repository root by walking up from dir to the directory
// holding go.mod.
//
// The scanners are whole-TREE, so they need the tree, and a test's working
// directory is its own package. Walking up to go.mod is how a test locates the
// root without a hard-coded relative path that breaks when a package moves.
func Root(dir string) (string, error) {
	current, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("guards: no go.mod at or above %s", dir)
		}
		current = parent
	}
}

// skippedDirs are directories no scanner descends into.
//
// GuardFixtureDir is the load-bearing entry: this package's own testdata holds
// DELIBERATE violations, planted so each scanner can be shown to fire. Scanning
// them from the repository sweep would report the fixtures as defects and make
// the whole suite permanently red.
//
// It is excluded by exact path rather than by the name "testdata", so a real
// violation in some other package's testdata is still found. A blanket
// exclusion would be the scanner blinding itself, which is the failure this
// package is about.
var skippedDirs = map[string]struct{}{
	".git":     {},
	"coverage": {},
	".deps":    {},
	"vendor":   {},
}

// GuardFixtureDir is this package's fixture root, relative to the repository
// root. See skippedDirs.
const GuardFixtureDir = "internal/guards/testdata"

// walk visits every file under root that matches keep, in a stable order,
// skipping the directories above and this package's own fixtures.
func walk(root string, keep func(rel string) bool) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if entry.IsDir() {
			if _, skip := skippedDirs[entry.Name()]; skip {
				return filepath.SkipDir
			}
			if filepath.ToSlash(rel) == GuardFixtureDir {
				return filepath.SkipDir
			}
			return nil
		}
		if keep(filepath.ToSlash(rel)) {
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

// hasExt reports whether rel ends in any of the given extensions.
func hasExt(rel string, exts ...string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(rel, ext) {
			return true
		}
	}
	return false
}
