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

package preflightmatrix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DeviceMapperControl is the node every device-mapper row passes in.
const DeviceMapperControl = "/dev/mapper/control"

// ProbePackage is the probe's import path relative to the module root.
const ProbePackage = "./internal/preflightmatrix/probe"

// Host is everything the matrix touches outside this process. The command
// wires the real one; tests wire fakes, because the rows themselves can only
// run on a Docker-capable host with device-mapper.
type Host struct {
	// Ready reports whether the container runtime is present and answering.
	Ready func(ctx context.Context) error

	// DeviceExists reports whether a device node exists on this host.
	DeviceExists func(path string) bool

	// BuildProbe builds the probe binary at out, statically, from the
	// working tree.
	BuildProbe func(ctx context.Context, out string) error

	// Container runs one container.
	Container Container
}

// DockerHost is the real host for runtime binary docker.
func DockerHost(docker string) Host {
	return Host{
		Ready: func(ctx context.Context) error {
			if _, err := exec.LookPath(docker); err != nil {
				return &PrerequisiteError{What: docker + " is not on PATH; this demonstration needs a container runtime", Err: err}
			}
			// #nosec G204 -- the runtime binary is the operator's own argument.
			if out, err := exec.CommandContext(ctx, docker, "info").CombinedOutput(); err != nil {
				return &PrerequisiteError{What: "cannot talk to the container runtime: " + strings.TrimSpace(string(out)), Err: err}
			}
			return nil
		},
		DeviceExists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		BuildProbe: func(ctx context.Context, out string) error {
			cmd := exec.CommandContext(ctx, "go", "build", "-o", out, ProbePackage)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				return &BuildError{Output: strings.TrimSpace(string(output)), Err: err}
			}
			return nil
		},
		Container: func(ctx context.Context, args []string) (string, bool, error) {
			// #nosec G204 -- the runtime binary is the operator's own argument;
			// the rest is the fixed matrix.
			output, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				// The container ran and the probe refused (or the
				// runtime refused the row); the output says which.
				return string(output), false, nil
			}
			return string(output), err == nil, err
		},
	}
}

// Main runs the whole demonstration on host, in image, reporting to w. It
// returns ErrRowsFailed when the matrix ran and a row misbehaved.
func Main(ctx context.Context, host Host, image string, w io.Writer) error {
	if err := host.Ready(ctx); err != nil {
		return err
	}
	if !host.DeviceExists(DeviceMapperControl) {
		return &PrerequisiteError{What: "this host has no " + DeviceMapperControl + ", so there is nothing to pass into a container"}
	}

	work, err := os.MkdirTemp("", "preflight-matrix-")
	if err != nil {
		return &PrerequisiteError{What: "creating a work directory", Err: err}
	}
	defer func() { _ = os.RemoveAll(work) }()

	fmt.Fprintln(w, "→ building the probe against this working tree")
	probe := filepath.Join(work, "preflight-probe")
	if buildErr := host.BuildProbe(ctx, probe); buildErr != nil {
		return buildErr
	}
	profiles, err := WriteProfiles(work)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "\n→ the matrix")
	failures, err := Run(ctx, host.Container, image, probe, Cases(profiles), w)
	if err != nil {
		return err
	}
	if failures != 0 {
		fmt.Fprintf(w, "\n✗ %d row(s) did not behave as the guard claims\n", failures)
		return ErrRowsFailed
	}
	fmt.Fprintln(w, "\n✓ the guard refuses every misconfigured container and passes the correct one")
	return nil
}
