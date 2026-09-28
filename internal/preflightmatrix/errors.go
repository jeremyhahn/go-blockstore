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

import "errors"

// ErrRowsFailed reports that at least one row did not behave as the guard
// claims. It is distinct from the errors below: it means the matrix RAN.
var ErrRowsFailed = errors.New("preflightmatrix: at least one row did not behave as the guard claims")

// PrerequisiteError reports a host that cannot run the matrix at all.
type PrerequisiteError struct {
	// What names the missing prerequisite.
	What string

	// Err is the underlying failure, if any.
	Err error
}

func (e *PrerequisiteError) Error() string {
	msg := "preflightmatrix: " + e.What
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *PrerequisiteError) Unwrap() error { return e.Err }

// ProfileError reports a seccomp profile that could not be generated.
type ProfileError struct {
	Path string
	Err  error
}

func (e *ProfileError) Error() string {
	return "preflightmatrix: writing the seccomp profile " + e.Path + ": " + e.Err.Error()
}

func (e *ProfileError) Unwrap() error { return e.Err }

// BuildError reports a probe binary that did not build. A matrix that silently
// ran an old binary would be worse than no matrix, so this stops the run.
type BuildError struct {
	Output string
	Err    error
}

func (e *BuildError) Error() string {
	msg := "preflightmatrix: building the probe: " + e.Err.Error()
	if e.Output != "" {
		msg += "\n" + e.Output
	}
	return msg
}

func (e *BuildError) Unwrap() error { return e.Err }

// RowError reports a row the container runtime could not run at all.
type RowError struct {
	Row string
	Err error
}

func (e *RowError) Error() string {
	return "preflightmatrix: running the row " + `"` + e.Row + `"` + ": " + e.Err.Error()
}

func (e *RowError) Unwrap() error { return e.Err }
