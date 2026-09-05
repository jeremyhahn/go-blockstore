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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// skipMethods are the testing methods that make a test report success without
// having run.
// t.Parallel is deliberately absent: it changes when a test runs, not whether
// it runs, and listing it here would have been a scanner rejecting a practice
// the guidelines encourage.
var skipMethods = map[string]struct{}{
	"Skip":    {},
	"Skipf":   {},
	"SkipNow": {},
	"Short":   {},
}

// skipReceivers are the identifiers a testing handle conventionally has.
var skipReceivers = map[string]struct{}{
	"t":  {},
	"b":  {},
	"f":  {},
	"tb": {},
}

// SkipGuards refuses a runtime skip anywhere in the tree.
//
// # The rule
//
// conventions/testing-guidelines.md §No Skip Guards: a test that cannot run in
// an environment is fixed by FIXING THE ENVIRONMENT, or gated behind a declared
// build tag whose tier actually provides the dependency — never by a runtime
// skip. A skipped test reports success. A suite of them reports a green run
// that establishes nothing, and the greenness is what stops anybody looking.
//
// That is not a hypothetical here: this effort has had green tests turn out to
// be false evidence repeatedly, and a skip is the mechanised form of it.
//
// # Why this parses Go instead of matching text
//
// A textual scanner fires on its own documentation. This file names t.Skip in
// prose half a dozen times, the convention document names it, and the testing
// guidelines quote it — so a grep-based version would report its own reasons
// for existing as violations, and the only way to ship it would be to weaken
// it. Parsing sees calls and nothing else.
//
// It also means a skip inside a string literal or a comment is correctly
// ignored, and a skip in a file excluded by a build tag is correctly FOUND:
// go/parser reads the file whatever its tags say, which is the whole point of a
// whole-tree scanner. A tag-gated file is exactly where a skip hides.
func SkipGuards() Scanner {
	return Scanner{
		Name: "no-runtime-skip",
		What: "a test that skips at run time reports success without having run",
		Scan: func(root string) (Result, error) {
			files, err := walk(root, func(rel string) bool {
				return hasExt(rel, ".go")
			})
			if err != nil {
				return Result{}, err
			}

			result := Result{Examined: files}
			for _, rel := range files {
				findings, err := scanGoForSkips(root, rel)
				if err != nil {
					return Result{}, err
				}
				result.Findings = append(result.Findings, findings...)
			}
			return result, nil
		},
	}
}

// scanGoForSkips parses one file and reports every runtime skip in it.
func scanGoForSkips(root, rel string) ([]Finding, error) {
	// #nosec G304 -- rel comes from walk over the repository tree, not from a
	// caller; the scanner's whole job is to read the repository's own files.
	source, err := os.ReadFile(filepathJoin(root, rel))
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, source, parser.ParseComments)
	if err != nil {
		// A file this package cannot parse is reported as a scan failure by the
		// caller rather than skipped. A parser error that silently produced
		// zero findings would be the scanner failing open on exactly the file
		// most likely to be unusual.
		return nil, err
	}

	var findings []Finding
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		method := selector.Sel.Name
		if _, watched := skipMethods[method]; !watched {
			return true
		}

		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}

		switch {
		case method == "Short" && receiver.Name == "testing":
			findings = append(findings, Finding{
				File: rel, Line: fset.Position(call.Pos()).Line,
				Message: "testing.Short() gates a test on a flag, which is a runtime skip by another name. " +
					"Gate it behind a declared build tag whose tier provides the dependency, or fix the environment " +
					"(conventions/testing-guidelines.md §No Skip Guards).",
			})
		case method != "Short":
			if _, isHandle := skipReceivers[receiver.Name]; !isHandle {
				return true
			}
			findings = append(findings, Finding{
				File: rel, Line: fset.Position(call.Pos()).Line,
				Message: receiver.Name + "." + method + " makes this test report SUCCESS without having run. " +
					"Fix the environment, or gate the test behind a declared build tag whose tier actually provides " +
					"what it needs (conventions/testing-guidelines.md §No Skip Guards).",
			})
		}
		return true
	})
	return findings, nil
}

// filepathJoin is filepath.Join with the slash-separated relative paths this
// package carries. It exists so the scanners can hold one path spelling.
func filepathJoin(root, rel string) string {
	return root + string(os.PathSeparator) + strings.ReplaceAll(rel, "/", string(os.PathSeparator))
}
