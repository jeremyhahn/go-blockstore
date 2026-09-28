// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package releasability is the gate that keeps this repository publicly
// releasable. Everything tracked here is published, so the gate reads every
// tracked file and reports each one that must change before it can ship.
//
// # What it refuses
//
//   - A lab address, internal domain, fleet hostname or owner path in any
//     tracked text, matched case-insensitively, line by line — and in the
//     target text of every tracked symlink, which is read and never followed.
//   - A shell script, recognized by its extension OR by its shebang: the
//     public release is Go only, and a script renamed to drop its ".sh" is
//     still a script.
//   - An AI agent's instruction or state file.
//   - Certificate or key material, or certificate tooling configuration.
//   - A symlink whose target leaves the tree.
//
// # It fails closed
//
// A tracked file the gate cannot read as text — a binary (a NUL byte in its
// first 8 KiB, git's own test), a file over MaxFileSize, a submodule, a file
// missing from the working tree — FAILS the gate unless ExemptFile lists it
// with a one-line reason. There are no silent skips: a file the gate did not
// read is a file whose contents nobody has checked, and "unread" must not be
// reported the same way as "clean". An exemption that exempts nothing fails
// too, so the list can only shrink.
//
// There is deliberately no inline waiver. Every value the gate refuses has a
// public equivalent (RFC 5737 addresses, RFC 2606 names, repository-relative
// paths), so a waiver would only ever be a hole.
//
// # Resolution is textual
//
// It needs no build tags, no module loading and no parser, so it runs on every
// tree state including one that does not compile, and it reads Markdown, YAML,
// Makefiles and testdata as readily as Go. The file list is the git index:
// a file is published because it is tracked.
//
// See docs/release/public-releasability.md for the rule and how to act on a
// finding.
package releasability

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ExemptFile is the committed list of tracked files the gate may not be able to
// read, each with the reason it ships anyway. It lives at the repository root.
const ExemptFile = "releasability-exempt.txt"

// MaxFileSize is the largest tracked file the gate reads. Nothing in this tree
// comes near it; a file that does is either generated or binary, and has to be
// looked at by a person and exempted by name.
const MaxFileSize = 1 << 20

// binarySniff is how much of a file is examined for a NUL byte before it is
// called binary. It is git's own heuristic, at the 8 KiB the gate rule states.
const binarySniff = 8 << 10

// excerptLimit bounds the quoted line in a report.
const excerptLimit = 160

// Finding is one thing that must change before this tree can be published.
type Finding struct {
	// Path is slash-separated and relative to the repository root.
	Path string

	// Line is 1-based; 0 when the finding is about the file as a whole.
	Line int

	// Rule says what is wrong.
	Rule Rule

	// Match is the offending text exactly as it appears, when there is one.
	Match string

	// Message says what to do instead.
	Message string
}

// String renders a finding in the file:line: form editors and CI logs link.
func (f Finding) String() string {
	loc := f.Path
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	if f.Match != "" {
		return fmt.Sprintf("%s: [%s] %q -- %s", loc, f.Rule, f.Match, f.Message)
	}
	return fmt.Sprintf("%s: [%s] %s", loc, f.Rule, f.Message)
}

// Result is what a scan examined and what it found. Examined is reported on a
// passing run too: it is the evidence that the pass means anything.
type Result struct {
	// Examined is the number of tracked files the scan looked at.
	Examined int

	// Exempted is the number of those accepted unread through ExemptFile.
	Exempted int

	// Findings is everything that must change.
	Findings []Finding
}

// Root returns the top of the git work tree containing dir.
func Root(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", &ListError{Root: dir, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return strings.TrimSpace(string(out)), nil
}

// TrackedFiles lists the paths in the git index at root, slash-separated,
// relative to it and sorted. The index is the right manifest: a file is
// published because it is tracked, and untracked litter ships nowhere.
func TrackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &ListError{Root: root, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// ScanRepo is the gate: it scans every tracked file under root against the
// exemptions committed in root's ExemptFile. It returns ErrFindings alongside
// the result when the tree is not releasable.
func ScanRepo(root string) (Result, error) {
	files, err := TrackedFiles(root)
	if err != nil {
		return Result{}, err
	}
	exempt, err := LoadExemptions(root)
	if err != nil {
		return Result{}, err
	}
	return Scan(root, files, exempt)
}

// LoadExemptions reads root's ExemptFile. A missing file is an empty list —
// that exempts nothing, which is the fail-closed reading.
func LoadExemptions(root string) (map[string]string, error) {
	handle, err := os.Open(filepath.Join(root, ExemptFile))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, &ExemptionError{Reason: "cannot be read", Err: err}
	}
	defer func() { _ = handle.Close() }()
	return ParseExemptions(handle)
}

// ParseExemptions reads an exemption list: one tracked path per line, then
// whitespace, then the reason it ships unread. Blank lines and lines beginning
// with "#" are ignored. A path with no reason, or a path listed twice, is
// refused: an exemption that does not say why is not one.
func ParseExemptions(r io.Reader) (map[string]string, error) {
	exempt := map[string]string{}
	scanner := bufio.NewScanner(r)
	number := 0
	for scanner.Scan() {
		number++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, reason := line, ""
		if gap := strings.IndexAny(line, " \t"); gap >= 0 {
			name, reason = line[:gap], strings.TrimSpace(line[gap:])
		}
		if reason == "" {
			return nil, &ExemptionError{Line: number, Reason: "entry " + name + " states no reason"}
		}
		if _, dup := exempt[name]; dup {
			return nil, &ExemptionError{Line: number, Reason: "entry " + name + " is listed twice"}
		}
		exempt[name] = reason
	}
	if err := scanner.Err(); err != nil {
		return nil, &ExemptionError{Reason: "cannot be read", Err: err}
	}
	return exempt, nil
}

// Scan checks the named files, interpreted relative to root. exempt maps a
// path to the reason it may ship unread; it accepts ONLY RuleUnreadable. A
// shell script, an agent file or key material cannot be exempted, because
// there is no reason one ships.
//
// It returns ErrNothingExamined for an empty file list, and ErrFindings with
// the populated Result when anything must change.
func Scan(root string, files []string, exempt map[string]string) (Result, error) {
	if len(files) == 0 {
		return Result{}, ErrNothingExamined
	}
	result := Result{Examined: len(files)}
	used := map[string]bool{}
	for _, name := range files {
		findings, unreadable := scanFile(root, name)
		if unreadable != nil {
			if _, ok := exempt[name]; ok {
				used[name] = true
				result.Exempted++
			} else {
				findings = append(findings, *unreadable)
			}
		}
		result.Findings = append(result.Findings, findings...)
	}
	stale := make([]string, 0, len(exempt))
	for name := range exempt {
		if !used[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		result.Findings = append(result.Findings, Finding{
			Path: ExemptFile, Rule: RuleStaleExemption, Match: name,
			Message: "this entry exempts nothing — the path is not tracked, or it is text the gate reads anyway; delete the entry",
		})
	}
	if len(result.Findings) > 0 {
		return result, ErrFindings
	}
	return result, nil
}

// scanFile applies every rule to one tracked file. The second result is the
// finding to report if the file could not be read as text and is not exempt;
// it is separate so Scan can consult the exemption list.
func scanFile(root, name string) ([]Finding, *Finding) {
	var findings []Finding
	if isAgentFile(name) {
		findings = append(findings, Finding{
			Path: name, Rule: RuleAgentFile,
			Message: "AI agent instructions and state are not part of the product; untrack it and add it to .gitignore",
		})
	}
	if isCertTooling(name) {
		findings = append(findings, Finding{
			Path: name, Rule: RuleCertTooling,
			Message: "key and certificate material does not ship; generate test material at run time",
		})
	}
	if shellExtensions[strings.ToLower(path.Ext(name))] {
		findings = append(findings, Finding{
			Path: name, Rule: RuleShellScript,
			Message: "the public release is Go only; rewrite it as a Go program or a Makefile recipe",
		})
	}

	full := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Lstat(full)
	if err != nil {
		return findings, unreadable(name, "cannot be examined: "+err.Error())
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return append(findings, scanSymlink(name, full)...), nil
	case info.IsDir():
		// A gitlink: the index names a commit in another repository,
		// whose contents this gate never sees.
		return findings, unreadable(name, "is a submodule, whose contents the gate cannot read")
	case !info.Mode().IsRegular():
		return findings, unreadable(name, "is not a regular file")
	case info.Size() > MaxFileSize:
		return findings, unreadable(name, fmt.Sprintf("is %d bytes, over the %d-byte cap", info.Size(), MaxFileSize))
	}

	// #nosec G304 -- name comes from the git index of the tree being scanned.
	content, err := os.ReadFile(full)
	if err != nil {
		return findings, unreadable(name, "cannot be read: "+err.Error())
	}
	head := content
	if len(head) > binarySniff {
		head = head[:binarySniff]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return findings, unreadable(name, "is binary (a NUL byte in its first 8 KiB)")
	}

	if shell := shebangShell(content); shell != "" {
		findings = append(findings, Finding{
			Path: name, Line: 1, Rule: RuleShellScript, Match: shell,
			Message: "a " + shell + " shebang makes this a shell script whatever it is called; the public release is Go only",
		})
	}
	return append(findings, scanText(name, string(content))...), nil
}

// unreadable builds the fail-closed finding for a file the gate did not read.
func unreadable(name, why string) *Finding {
	return &Finding{
		Path: name, Rule: RuleUnreadable,
		Message: "this file " + why + ", so the gate has not checked it; make it text, or list it in " +
			ExemptFile + " with the reason it ships",
	}
}

// scanSymlink checks a symlink's target text without following it: the text
// is what is published, and following it would read a file on whatever
// machine the gate happens to run on.
func scanSymlink(name, full string) []Finding {
	target, err := os.Readlink(full)
	if err != nil {
		return []Finding{*unreadable(name, "is a symlink whose target cannot be read: "+err.Error())}
	}
	findings := scanText(name, target)
	resolved := path.Join(path.Dir(name), filepath.ToSlash(target))
	if filepath.IsAbs(target) || resolved == ".." || strings.HasPrefix(resolved, "../") {
		findings = append(findings, Finding{
			Path: name, Rule: RuleSymlinkEscape, Match: target,
			Message: "this symlink points outside the repository, so it names a path on one machine and dangles on every other; " +
				"commit the content or point inside the tree",
		})
	}
	return findings
}

// scanText applies the content rules to every line of text.
func scanText(name, text string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(text, "\n") {
		number := i + 1
		for _, match := range labAddresses(line) {
			findings = append(findings, Finding{
				Path: name, Line: number, Rule: RuleLabAddress, Match: match,
				Message: addressGuidance + "\n\t" + excerpt(line),
			})
		}
		for _, rule := range contentRules {
			for _, match := range rule.expr.FindAllString(line, -1) {
				findings = append(findings, Finding{
					Path: name, Line: number, Rule: rule.rule, Match: match,
					Message: rule.guidance + "\n\t" + excerpt(line),
				})
			}
		}
		if match := pemArmor.FindString(line); match != "" {
			findings = append(findings, Finding{
				Path: name, Line: number, Rule: RuleCertTooling, Match: match,
				Message: "key and certificate material does not ship; generate test material at run time",
			})
		}
	}
	return findings
}

// excerpt trims and bounds a line for the report.
func excerpt(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) <= excerptLimit {
		return trimmed
	}
	return trimmed[:excerptLimit] + " ..."
}

// Report writes a scan's outcome for an engineer to act on. It leads with what
// was examined, because on a passing run that count is the only evidence the
// pass means anything.
func Report(w io.Writer, result Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "releasability: examined %d tracked file(s), %d accepted unread via %s\n",
		result.Examined, result.Exempted, ExemptFile)
	if len(result.Findings) == 0 {
		b.WriteString("releasability: clean — the tracked tree is publicly releasable\n")
	} else {
		fmt.Fprintf(&b, "releasability: %d finding(s) — this tree ships publicly:\n\n", len(result.Findings))
		for _, f := range result.Findings {
			fmt.Fprintf(&b, "%s\n\n", f)
		}
		b.WriteString("See docs/release/public-releasability.md for the rule and what to use instead.\n")
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return &ReportError{Err: err}
	}
	return nil
}
