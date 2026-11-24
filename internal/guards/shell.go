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
	"bufio"
	"os"
	"strings"
)

// failOpenMarker annotates a deliberate exit-swallow with its reason.
const failOpenMarker = "guard:fail-open"

// fleetManagedFiles are template-deployed files this repository cannot annotate; matched by exact path.
var fleetManagedFiles = map[string]struct{}{
	".github/workflows/automerge.yml": {},
}

// failOpenPatterns are the shell constructions that turn a failed command into
// a successful one.
var failOpenPatterns = []string{"|| true", "||true", "|| :", "||:"}

// FailOpenShell refuses `|| true` in shell unless the line or the one above carries `guard:fail-open <reason>`.
func FailOpenShell() Scanner {
	return Scanner{
		Name: "no-unexplained-fail-open",
		What: "a swallowed exit status makes a failing command look like a clean one",
		Scan: func(root string) (Result, error) {
			files, err := walk(root, func(rel string) bool {
				if _, managed := fleetManagedFiles[rel]; managed {
					return false
				}
				return hasExt(rel, ".sh", ".yml", ".yaml") ||
					rel == "Makefile" || strings.HasSuffix(rel, "/Makefile")
			})
			if err != nil {
				return Result{}, err
			}

			result := Result{Examined: files}
			for _, rel := range files {
				findings, err := scanShellForFailOpen(root, rel)
				if err != nil {
					return Result{}, err
				}
				result.Findings = append(result.Findings, findings...)
			}
			return result, nil
		},
	}
}

// scanShellForFailOpen reads one file and reports unexplained exit-swallows.
func scanShellForFailOpen(root, rel string) ([]Finding, error) {
	// #nosec G304 -- rel comes from walk over the repository tree.
	handle, err := os.Open(filepathJoin(root, rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()

	var (
		findings []Finding
		previous string
		number   int
	)

	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		number++

		if !isFailOpen(line) {
			previous = line
			continue
		}
		if strings.Contains(line, failOpenMarker) || strings.Contains(previous, failOpenMarker) {
			previous = line
			continue
		}
		findings = append(findings, Finding{
			File: rel, Line: number,
			Message: "this swallows the command's exit status, so a FAILING command is indistinguishable from a " +
				"clean one — and if its output is consumed, an unreadable answer becomes an empty answer. " +
				"Either handle the failure, or keep it and say why with a `# " + failOpenMarker + " <reason>` " +
				"comment on this line or the one above.",
		})
		previous = line
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// isFailOpen reports whether a line swallows an exit status in a command position; comments do not count.
func isFailOpen(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	// A Makefile recipe comment, and a shell comment after a command, both put
	// the construction beyond the "#". Only what precedes it is executed.
	if hash := strings.Index(trimmed, "#"); hash >= 0 {
		trimmed = trimmed[:hash]
	}
	for _, pattern := range failOpenPatterns {
		if strings.Contains(trimmed, pattern) {
			return true
		}
	}
	return false
}
