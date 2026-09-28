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

package releasability

import (
	"errors"
	"strconv"
)

// ErrNothingExamined reports a scan over an empty file list. Zero tracked files
// and a clean tree produce the same finding count; they must not produce the
// same verdict, so an empty scan is a failure rather than a pass.
var ErrNothingExamined = errors.New("releasability: the scan examined no tracked files, so its silence means nothing")

// ErrFindings reports that the tree is not publicly releasable. It is distinct
// from the errors below because findings mean the gate WORKED: a caller that
// folded the two together would lose the difference between "the tree is
// dirty" and "the scan never happened".
var ErrFindings = errors.New("releasability: the tracked tree is not publicly releasable")

// ListError reports that git could not enumerate the tracked files.
type ListError struct {
	// Root is the directory git was asked about.
	Root string

	// Stderr is what git said, trimmed.
	Stderr string

	// Err is the underlying failure.
	Err error
}

func (e *ListError) Error() string {
	msg := "releasability: listing the tracked files under " + e.Root + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += " (" + e.Stderr + ")"
	}
	return msg
}

func (e *ListError) Unwrap() error { return e.Err }

// ExemptionError reports a releasability-exempt.txt the gate refuses to trust.
// An exemption list that does not say why it exempts something is a defect in
// the gate, not a pass.
type ExemptionError struct {
	// Line is the 1-based line of the offending entry; 0 when the file as a
	// whole could not be read.
	Line int

	// Reason says what is wrong with the entry.
	Reason string

	// Err is the underlying failure, if any.
	Err error
}

func (e *ExemptionError) Error() string {
	msg := "releasability: " + ExemptFile
	if e.Line > 0 {
		msg += ":" + strconv.Itoa(e.Line)
	}
	msg += ": " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ExemptionError) Unwrap() error { return e.Err }

// ReportError reports that the findings could not be written out.
type ReportError struct {
	// Err is the underlying write failure.
	Err error
}

func (e *ReportError) Error() string {
	return "releasability: writing the report: " + e.Err.Error()
}

func (e *ReportError) Unwrap() error { return e.Err }
