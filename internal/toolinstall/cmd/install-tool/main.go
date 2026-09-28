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

// Command install-tool installs a pinned, checksum-verified analyser binary.
//
//	go run ./internal/toolinstall/cmd/install-tool shellcheck <install-dir> [version]
//	go run ./internal/toolinstall/cmd/install-tool trivy <install-dir> [version]
//
// It is the ONE installer for each tool: `make install-tools` and CI both run
// it, so the binary on a developer's machine and the one in CI are the same.
// With no version, shellcheck installs toolinstall.ShellcheckVersion and trivy
// reads .trivy-version from the working directory, strictly.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-blockstore/internal/toolinstall"
)

// Exit statuses: 1 means the install failed, 2 means the invocation is wrong.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// trivyVersionFile is the single declaration of the trivy version, shared with
// the Makefile and the nightly workflow.
const trivyVersionFile = ".trivy-version"

const usage = "usage: install-tool <shellcheck|trivy> <install-dir> [version]\n"

// run is main with its edges handed in, so every exit status is reachable from
// a test.
func run(ctx context.Context, args []string, out, errOut io.Writer, installer toolinstall.Installer) int {
	if len(args) < 2 || len(args) > 3 || args[1] == "" {
		fmt.Fprint(errOut, usage)
		return exitUsage
	}
	var (
		tool    toolinstall.Tool
		version string
	)
	switch args[0] {
	case "shellcheck":
		tool, version = toolinstall.Shellcheck(), toolinstall.ShellcheckVersion
	case "trivy":
		tool = toolinstall.Trivy()
	default:
		fmt.Fprintf(errOut, "install-tool: unknown tool %q\n%s", args[0], usage)
		return exitUsage
	}
	for _, explicit := range args[2:] {
		version = explicit
	}
	if version == "" {
		v, err := toolinstall.ReadVersionFile(trivyVersionFile)
		if err != nil {
			fmt.Fprintf(errOut, "%v\n", err)
			return exitFailed
		}
		version = v
	}

	installer.Log = out
	if err := installer.Install(ctx, tool, version, args[1]); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return exitFailed
	}
	return exitOK
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, toolinstall.Installer{})
	stop()
	os.Exit(code)
}
