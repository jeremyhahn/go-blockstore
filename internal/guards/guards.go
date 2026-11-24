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

// Package guards holds whole-tree scanners; each must fire on a violating fixture, stay silent on a clean one and examine a non-empty file set.
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

// Result is what a scanner examined and what it found; an empty Examined is a failure.
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

	// Scan reports what it examined and found under root; it errors only when the scan itself failed.
	Scan func(root string) (Result, error)
}

// All returns every scanner in a stable order, the same list the tests and the command line use.
func All() []Scanner {
	return []Scanner{
		SkipGuards(),
		FailOpenShell(),
		PrivilegedAsRemedy(),
		KeyMaterialCustody(),
	}
}

// ErrScanFoundNothingToExamine reports a scanner that read no files.
var ErrScanFoundNothingToExamine = errors.New("guards: the scanner examined no files, so its silence means nothing")

// Run executes every scanner against root and returns the findings by scanner name; a scanner that examined nothing is an error.
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

// Root finds the repository root by walking up from dir to the directory holding go.mod.
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

// skippedDirs are directories no scanner descends into; the guard fixtures are excluded by exact path.
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
