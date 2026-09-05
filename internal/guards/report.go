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

// ErrNoScanners reports a sweep with nothing to sweep.
//
// It is the top of the same fail-closed chain as ErrScanFoundNothingToExamine,
// one level up: a sweep over zero scanners produces zero findings and exits 0,
// which is byte-for-byte what a clean tree produces. That is not a theoretical
// confusion — it is the observation that opened #47. A guard sweep over this
// repository printed nothing, and the nothing meant "there are no guards".
var ErrNoScanners = errors.New("guards: the sweep had no scanners to run, so its silence means nothing")

// ErrFindings reports that the tree violates at least one guard.
//
// It is separate from the errors above because the two say opposite things
// about the instrument: findings mean the scanners WORKED, and a caller that
// collapsed them into one exit status would lose the difference between "the
// tree is dirty" and "the scan never happened".
var ErrFindings = errors.New("guards: the tree violates at least one guard")

// Report runs every scanner against root and writes an operator-facing account
// of what was examined and what was found.
//
// The output leads with the EXAMINED counts rather than the findings, because
// those counts are the evidence that the run means anything. A reader who sees
// only "no findings" cannot tell a clean tree from a scanner that read nothing;
// a reader who sees "no-runtime-skip: examined 127 files, clean" can.
//
// It returns:
//
//   - ErrNoScanners if the scanner list is empty.
//   - the joined scan errors if any scanner failed or examined nothing.
//   - ErrFindings if the tree is dirty.
//   - nil only when every scanner ran, read something, and found nothing.
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
