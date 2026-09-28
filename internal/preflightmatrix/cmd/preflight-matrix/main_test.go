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

package main

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/preflightmatrix"
)

// hostThat returns a host factory whose runtime is never ready, failing with
// err, and records the binary and image it was asked for.
func hostThat(err error, docker *string) func(string) preflightmatrix.Host {
	return func(binary string) preflightmatrix.Host {
		*docker = binary
		return preflightmatrix.Host{Ready: func(context.Context) error { return err }}
	}
}

func TestRunUsage(t *testing.T) {
	var docker string
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"a", "b"}, "", &bytes.Buffer{}, &errOut, hostThat(nil, &docker)); code != 2 {
		t.Fatalf("run with two arguments = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "usage:") || docker != "" {
		t.Errorf("stderr = %q, runtime = %q", errOut.String(), docker)
	}
}

func TestRunReportsAHostThatCannotRunTheMatrix(t *testing.T) {
	var docker string
	var errOut bytes.Buffer
	notReady := &preflightmatrix.PrerequisiteError{What: "podman is not on PATH"}
	if code := run(context.Background(), []string{"podman"}, "", &bytes.Buffer{}, &errOut, hostThat(notReady, &docker)); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if docker != "podman" || !strings.Contains(errOut.String(), "podman is not on PATH") {
		t.Errorf("runtime = %q, stderr = %q", docker, errOut.String())
	}
}

func TestRunDistinguishesFailedRows(t *testing.T) {
	var docker string
	var errOut bytes.Buffer
	if code := run(context.Background(), nil, "", &bytes.Buffer{}, &errOut, hostThat(preflightmatrix.ErrRowsFailed, &docker)); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if docker != "docker" || errOut.Len() != 0 {
		t.Errorf("runtime = %q; failed rows are already reported on stdout, stderr = %q", docker, errOut.String())
	}
}

func TestRunPasses(t *testing.T) {
	var images []string
	host := func(string) preflightmatrix.Host {
		return preflightmatrix.Host{
			Ready:        func(context.Context) error { return nil },
			DeviceExists: func(string) bool { return true },
			BuildProbe:   func(_ context.Context, out string) error { return os.WriteFile(out, []byte("probe"), 0o600) },
			Container: func(_ context.Context, args []string) (string, bool, error) {
				mode := args[len(args)-1]
				images = append(images, args[len(args)-3])
				narrow := slices.ContainsFunc(args, func(a string) bool { return strings.HasSuffix(a, "/narrow.json") })
				switch {
				case mode == preflightmatrix.ModeNetAdmin && slices.Contains(args, "NET_ADMIN") && !slices.Contains(args, "SYS_ADMIN"),
					mode == preflightmatrix.ModeDMKeyring && narrow && slices.Contains(args, "--device") &&
						slices.Contains(args, "SYS_ADMIN") && !slices.Contains(args, "65534"):
					return "PASS\n", true, nil
				}
				var needles []string
				for _, c := range preflightmatrix.Cases(preflightmatrix.Profiles{}) {
					needles = append(needles, c.Needle)
				}
				return "REFUSED\n" + strings.Join(needles, " "), false, nil
			},
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, "", &out, &errOut, host); code != 0 {
		t.Fatalf("run = %d, want 0\n%s%s", code, out.String(), errOut.String())
	}
	if len(images) == 0 || images[0] != defaultImage {
		t.Errorf("images = %v, want the default %s", images, defaultImage)
	}
	images = nil
	if code := run(context.Background(), nil, "busybox:1", &out, &errOut, host); code != 0 || images[0] != "busybox:1" {
		t.Errorf("run with an image override = %d, images %v", code, images)
	}
}
