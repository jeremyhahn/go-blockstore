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

// failOpenMarker is the annotation that declares a deliberate exit-swallow and
// says why.
//
// The scanner takes an ANNOTATION rather than an exemption list because the
// thing worth having is the reason, written next to the code, where the next
// reader meets it. A central allowlist records that somebody once decided;
// it does not record what they decided or why, and it drifts out of sight.
const failOpenMarker = "guard:fail-open"

// fleetManagedFiles are files this repository does not own and cannot annotate,
// so the fail-open scanner does not read them.
//
// automerge.yml is deployed into every repository byte-for-byte from the
// company template by infra/gitea/scripts/deploy-gitea-workflows.sh, which
// checks that each copy is identical. A `# guard:fail-open` line added here
// would be overwritten on the next deploy, or would fail that check. This repo
// cannot make the change, and a scanner that keeps main red over it fails every
// PR. Its exit-swallows are reviewed where the file is written, in the company
// repository (automatethethings software/templates/github-actions). Measured
// 2026-10-05: automerge v7 line 616, `read ... < <(...; echo) || true`, turned
// main's Lint red (#78).
//
// The match is on the exact path. Every other workflow, script and Makefile in
// this repository, including any other file under .github/workflows/, is still
// scanned.
var fleetManagedFiles = map[string]struct{}{
	".github/workflows/automerge.yml": {},
}

// failOpenPatterns are the shell constructions that turn a failed command into
// a successful one.
var failOpenPatterns = []string{"|| true", "||true", "|| :", "||:"}

// FailOpenShell refuses a swallowed exit status in shell without a stated
// reason.
//
// # The rule
//
// `cmd || true` makes a FAILING command indistinguishable from a succeeding
// one, and when its output is then consumed, an unreadable answer becomes an
// empty answer. That is not a hypothetical here: a host-safety guard in this
// repository used `... | grep -c ... || true`, so a failing dmsetup read
// reported "no mappings" — the guard passed by being unable to look.
//
// # It requires an annotation rather than forbidding the construction
//
// Plenty of uses are correct. `grep ... || true` around a list that is
// legitimately empty is right, and a scanner that refused it outright would be
// suppressed within a week — which is the real failure mode of a strict guard,
// and worse than not having one, because a suppressed guard still looks like
// coverage.
//
// So the rule is: swallow the exit if you mean to, and say why on the line or
// the one above it:
//
//	vgs --noheadings -o vg_name 2>/dev/null || true  # guard:fail-open an absent vgs means no groups
//
// The annotation is greppable, travels with the code, and turns a silent
// decision into a reviewable one.
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

// isFailOpen reports whether a line swallows an exit status in a command
// position.
//
// A COMMENT that merely discusses the construction is not a violation, and
// getting that wrong would make the scanner fire on its own documentation and
// on the comments explaining previous incidents — several of which exist in
// this repository precisely because the bug was worth recording.
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
