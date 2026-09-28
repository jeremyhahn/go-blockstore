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

// Command releasability is the public-releasability gate `make releasability`
// and the CI Lint job run. It scans every tracked file and exits non-zero if
// the tree cannot be published as it stands.
//
// It prints the number of files it examined whether or not anything fired, so
// a passing run carries the evidence that the scan happened.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-blockstore/internal/releasability"
)

// Exit statuses. They are distinguished because a caller acts on them
// differently: 1 means look at the tree, 2 means look at the invocation.
const (
	exitClean      = 0
	exitFindings   = 1
	exitCannotScan = 2
)

// run is main with its edges handed in, so every exit status is reachable from
// a test.
func run(out, errOut io.Writer, dir string) int {
	root, err := releasability.Root(dir)
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return exitCannotScan
	}
	result, err := releasability.ScanRepo(root)
	if err != nil && !errors.Is(err, releasability.ErrFindings) {
		fmt.Fprintf(errOut, "%v\n", err)
		return exitCannotScan
	}
	if reportErr := releasability.Report(out, result); reportErr != nil {
		fmt.Fprintf(errOut, "%v\n", reportErr)
		return exitCannotScan
	}
	if err != nil {
		return exitFindings
	}
	return exitClean
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr, "."))
}
