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

// skipMethods are the testing methods that report success without running; t.Parallel is not one.
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

// SkipGuards refuses a runtime skip anywhere in the tree, parsing Go so tag-gated files are read and comments and strings are ignored.
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
		// An unparsable file is a scan failure for the caller, never zero findings.
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
