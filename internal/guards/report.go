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
	"io"
	"sort"
)

// ErrNoScanners reports a sweep with no scanners, which would otherwise look like a clean tree.
var ErrNoScanners = errors.New("guards: the sweep had no scanners to run, so its silence means nothing")

// ErrFindings reports that the tree violates at least one guard.
var ErrFindings = errors.New("guards: the tree violates at least one guard")

// Report runs every scanner against root, writes examined counts and findings, and returns ErrNoScanners, scan errors, ErrFindings or nil.
func Report(out io.Writer, root string, scanners []Scanner) error {
	if len(scanners) == 0 {
		fmt.Fprintln(out, "FAIL: "+ErrNoScanners.Error())
		return ErrNoScanners
	}

	results, err := Run(root, scanners)
	if err != nil {
		fmt.Fprintf(out, "FAIL: the scan itself did not run, which is not the same as passing:\n  %v\n", err)
		return err
	}

	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)

	total := 0
	for _, name := range names {
		result := results[name]
		total += len(result.Findings)

		verdict := "clean"
		if len(result.Findings) > 0 {
			verdict = fmt.Sprintf("%d finding(s)", len(result.Findings))
		}
		fmt.Fprintf(out, "%s: examined %d file(s), %s\n", name, len(result.Examined), verdict)
	}

	if total == 0 {
		fmt.Fprintf(out, "OK: %d scanner(s) ran, every one of them read files, none of them fired\n", len(names))
		return nil
	}

	// The findings themselves come last and grouped, in the file:line:message
	// shape an editor jumps to, with the rule restated so the remedy does not
	// depend on the reader already knowing which guard is which.
	byName := make(map[string]Scanner, len(scanners))
	for _, scanner := range scanners {
		byName[scanner.Name] = scanner
	}
	for _, name := range names {
		result := results[name]
		if len(result.Findings) == 0 {
			continue
		}
		fmt.Fprintf(out, "\n%s — %s\n", name, byName[name].What)
		for _, finding := range result.Findings {
			fmt.Fprintf(out, "  %s\n", finding)
		}
	}
	fmt.Fprintf(out, "\nFAIL: %d finding(s) across %d scanner(s)\n", total, len(names))
	return ErrFindings
}
