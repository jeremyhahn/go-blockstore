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

//go:build linux

package mountinfo

import (
	"golang.org/x/sys/unix"
)

// DeviceNumber returns the major:minor of the block device at path, following symlinks; a non-block path is refused.
func DeviceNumber(path string) (uint32, uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, &DeviceError{Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, 0, &DeviceError{Path: path, Err: ErrNotBlockDevice}
	}
	// The conversions are needed on 32-bit Linux, where Rdev is uint32.
	//nolint:unconvert // required on 32-bit Linux, where Rdev is uint32
	return unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)), nil
}
