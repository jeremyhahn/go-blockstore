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

// Command guards is the entry point `make guards` and the CI Lint job run.
//
// # Why a binary and not just `go test -run TestGuards ./internal/guards/`
//
// That is what the first version did, and it is the very defect #47 is about
// wearing a different hat: `go test -run <pattern>` that matches NOTHING prints
// `ok` and exits 0. Rename a test, mistype the pattern, move the package, and
// the gate reports a clean run having executed no assertion at all — the same
// silence-reads-as-success shape as the empty guard sweep that opened the issue.
//
// This binary cannot do that. It refuses an empty scanner list, refuses a
// scanner that examined no files, and prints the examined counts whether or not
// anything fired, so the evidence that the sweep happened is in the output of a
// PASSING run rather than only a failing one.
//
// `make guards` runs this AND the package's own tests, because they answer
// different questions: this one asks whether the tree is clean, and the tests
// ask whether the scanners can still say "yes" at all.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-blockstore/internal/guards"
)

// Exit statuses. They are distinguished because a caller acts on them
// differently: 1 means look at the tree, 2 means look at the invocation.
const (
	exitClean      = 0
	exitFindings   = 1
	exitCannotScan = 2
)

// run is main with its edges handed in, so every exit status is reachable from
// a test. main() itself is the one line that cannot be.
//
// The scanner list is a parameter for the same reason: the dirty path is not
// reachable over a repository that passes its own guards, and an exit status no
// test has ever produced is an exit status nobody knows is right.
func run(out, errOut io.Writer, dir string, scanners []guards.Scanner) int {
	root, err := guards.Root(dir)
	if err != nil {
		fmt.Fprintf(errOut, "guards: %v\n", err)
		return exitCannotScan
	}

	if err := guards.Report(out, root, scanners); err != nil {
		return exitFindings
	}
	return exitClean
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr, ".", guards.All()))
}
