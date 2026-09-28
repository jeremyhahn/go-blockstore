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

// Command probe is the binary the preflight matrix runs inside each container.
// It calls pkg/preflight's own entry point — nothing is simulated — and prints
// PASS or REFUSED with the refusal. It is built by the matrix, statically,
// from the working tree, so a row never runs an old binary.
package main

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-blockstore/internal/preflightmatrix"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	os.Exit(preflightmatrix.Probe(context.Background(), mode, preflight.Check, os.Stdout))
}
