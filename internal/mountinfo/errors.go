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

package mountinfo

import "errors"

// The sentinels naming what is wrong with a record. They carry no data of their
// own — the record and its line number travel on ParseError, which wraps one of
// these — so they exist to be matched rather than to be read.
var (
	// ErrTooFewFields reports a record shorter than the fixed fields require.
	ErrTooFewFields = errors.New("mountinfo: record has too few fields")

	// ErrNoSeparator reports a record with no "-" dividing the optional fields
	// from the ones counted after it.
	ErrNoSeparator = errors.New("mountinfo: record has no field separator")

	// ErrTruncatedAfterSeparator reports a record whose separator is not
	// followed by the filesystem type, source and super options.
	ErrTruncatedAfterSeparator = errors.New("mountinfo: record ends after its separator")

	// ErrMalformedDeviceNumber reports a major:minor field that is not one.
	ErrMalformedDeviceNumber = errors.New("mountinfo: device number is not major:minor")

	// ErrNotBlockDevice reports a path that is not a block device, and so has no
	// device number to match a mount against.
	ErrNotBlockDevice = errors.New("mountinfo: path is not a block device")

	// ErrNotMounted reports a path with nothing mounted at it, where the caller
	// asked a question that only a mount can answer.
	//
	// Distinct from a false answer on purpose: "nothing is mounted here" and
	// "what is mounted here does not propagate" are different findings with
	// different fixes, and a guard that collapsed them would report the wrong
	// one at the moment somebody is trying to fix a deployment.
	ErrNotMounted = errors.New("mountinfo: nothing is mounted at that path")

	// ErrNotVisibleThere reports a path where something IS mounted and it is not
	// the device asked about.
	//
	// Distinct from ErrNotMounted because the fixes differ and so does the
	// hazard: nothing mounted is a mount that failed or was removed, while
	// something else mounted is another actor's filesystem on the same path —
	// whose propagation must not be read as this device's, and which must never
	// be unmounted on this device's behalf.
	ErrNotVisibleThere = errors.New("mountinfo: another filesystem is visible at that path")

	// ErrMalformedMountID reports a record whose mount id is not a number.
	ErrMalformedMountID = errors.New("mountinfo: mount id is not a number")

	// ErrMalformedParentID reports a record whose parent mount id is not a
	// number.
	//
	// Refused rather than defaulted to zero: the parent id is the edge that
	// makes the table a tree, and a record with no readable edge is one whose
	// visibility cannot be decided. A zero would not read as "unknown", it
	// would read as "no parent" — the shape treated as the top of the table and
	// therefore always reachable, which is the answer a caller acts on by
	// unmounting.
	ErrMalformedParentID = errors.New("mountinfo: parent mount id is not a number")

	// ErrUnsupportedPlatform reports that device numbers cannot be read here.
	ErrUnsupportedPlatform = errors.New("mountinfo: reading device numbers requires Linux")
)

// Unexported aliases, so parseLine reads as prose without repeating the package
// name it is already inside.
var (
	errTooFewFields            = ErrTooFewFields
	errNoSeparator             = ErrNoSeparator
	errTruncatedAfterSeparator = ErrTruncatedAfterSeparator
	errMalformedDeviceNumber   = ErrMalformedDeviceNumber
	errMalformedMountID        = ErrMalformedMountID
	errMalformedParentID       = ErrMalformedParentID
)

// ReadError reports that the mount table could not be read at all.
//
// Distinct from ParseError on purpose: this one means the table was never
// obtained, which a caller must not confuse with a table that was read and did
// not mention its device. That confusion is what asking findmnt made
// unavoidable.
type ReadError struct {
	// Path is the file that could not be read.
	Path string

	// Err is the underlying failure.
	Err error
}

func (e *ReadError) Error() string {
	return "mountinfo: reading " + e.Path + ": " + e.Err.Error()
}

func (e *ReadError) Unwrap() error { return e.Err }

// ParseError reports a record the format does not allow, with the record itself
// so the report is actionable rather than a line number to go and look up.
type ParseError struct {
	// Line is the 1-based record number.
	Line int

	// Text is the record as read.
	Text string

	// Err is the sentinel saying what is wrong with it.
	Err error
}

func (e *ParseError) Error() string {
	return "mountinfo: line " + itoa(e.Line) + ": " + e.Err.Error() + ": " + e.Text
}

func (e *ParseError) Unwrap() error { return e.Err }

// MountPointError reports a question about a path that the mount table could
// not answer, carrying the path so the report names it.
type MountPointError struct {
	// MountPoint is the path that was asked about.
	MountPoint string

	// Err is the underlying failure, or one of the sentinels above.
	Err error
}

func (e *MountPointError) Error() string {
	return "mountinfo: " + e.MountPoint + ": " + e.Err.Error()
}

func (e *MountPointError) Unwrap() error { return e.Err }

// DeviceError reports that a path's device number could not be determined, so
// no mount could be attributed to it.
type DeviceError struct {
	// Path is the device path.
	Path string

	// Err is the underlying failure, or one of the sentinels above.
	Err error
}

func (e *DeviceError) Error() string {
	return "mountinfo: identifying " + e.Path + ": " + e.Err.Error()
}

func (e *DeviceError) Unwrap() error { return e.Err }

// itoa keeps the error strings free of a fmt dependency, which is what the
// house rule against fmt.Errorf is guarding: an error built by formatting is an
// error nobody can match on.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
