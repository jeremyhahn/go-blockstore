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

// privilegedFlag is the thing no document, comment or script may recommend.
const privilegedFlag = "--privileged"

// warningMarkers turn a mention of --privileged into a warning; matched case-insensitively.
var warningMarkers = []string{
	"do not use",
	"do not",
	"don't",
	"never",
	"not the fix",
	"rather than",
	"instead of",
	"prefer",
	"avoid",
	"no --privileged",
	"without",
	"appears nowhere",
	"is not a remedy",
}

// PrivilegedAsRemedy refuses docs, shell scripts, CI YAML or the Makefile offering --privileged as a fix; Go source is not scanned.
func PrivilegedAsRemedy() Scanner {
	return Scanner{
		Name: "privileged-is-never-a-remedy",
		What: "--privileged grants everything and disables seccomp and the LSM; nothing may offer it as a fix",
		Scan: func(root string) (Result, error) {
			files, err := walk(root, func(rel string) bool {
				return hasExt(rel, ".md", ".sh", ".yml", ".yaml") ||
					rel == "Makefile" || strings.HasSuffix(rel, "/Makefile")
			})
			if err != nil {
				return Result{}, err
			}

			result := Result{Examined: files}
			for _, rel := range files {
				findings, scanErr := scanTextForPrivileged(root, rel)
				if scanErr != nil {
					return Result{}, scanErr
				}
				result.Findings = append(result.Findings, findings...)
			}
			return result, nil
		},
	}
}

// privilegedFinding builds the finding, so the two scanning paths cannot drift
// in what they tell an engineer to do.
func privilegedFinding(rel string, line int) Finding {
	return Finding{
		File: rel, Line: line,
		Message: "this mentions " + privilegedFlag + " without warning against it. It grants EVERY capability, " +
			"disables the seccomp profile and the LSM confinement wholesale, and exposes every host device, so it " +
			"is never the fix for a container that cannot do something — name the specific capability, device or " +
			"profile change instead. If this really is a warning, phrase it as one (\"Do NOT use " +
			privilegedFlag + "…\").",
	}
}

// mentionsWithoutWarning reports whether a line offers the flag rather than
// warning against it.
func mentionsWithoutWarning(text string) bool {
	if !strings.Contains(text, privilegedFlag) {
		return false
	}
	lowered := strings.ToLower(text)
	for _, marker := range warningMarkers {
		if strings.Contains(lowered, marker) {
			return false
		}
	}
	return true
}

// scanTextForPrivileged reads a documentation, shell or YAML file line by line.
func scanTextForPrivileged(root, rel string) ([]Finding, error) {
	// #nosec G304 -- rel comes from walk over the repository tree.
	handle, err := os.Open(filepathJoin(root, rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()

	var (
		findings []Finding
		number   int
	)
	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		number++
		if mentionsWithoutWarning(scanner.Text()) {
			findings = append(findings, privilegedFinding(rel, number))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}
