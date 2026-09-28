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

// Command preflight-matrix proves the startup privilege guard fires — and does
// not — in real containers. See package preflightmatrix for what each row
// demonstrates.
//
//	go run ./internal/preflightmatrix/cmd/preflight-matrix [docker-binary]
//
// PREFLIGHT_MATRIX_IMAGE overrides the image (default alpine:3). Run it from
// the module root: the probe is built from the working tree.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-blockstore/internal/preflightmatrix"
)

// defaultImage is the container image each row runs in.
const defaultImage = "alpine:3"

// run is main with its edges handed in, so every exit status is reachable from
// a test.
func run(ctx context.Context, args []string, image string, out, errOut io.Writer,
	host func(docker string) preflightmatrix.Host) int {
	if len(args) > 1 {
		fmt.Fprint(errOut, "usage: preflight-matrix [docker-binary]\n")
		return 2
	}
	docker := "docker"
	if len(args) == 1 {
		docker = args[0]
	}
	if image == "" {
		image = defaultImage
	}
	err := preflightmatrix.Main(ctx, host(docker), image, out)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, preflightmatrix.ErrRowsFailed):
		return 1
	default:
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv("PREFLIGHT_MATRIX_IMAGE"), os.Stdout, os.Stderr, preflightmatrix.DockerHost)
	stop()
	os.Exit(code)
}
