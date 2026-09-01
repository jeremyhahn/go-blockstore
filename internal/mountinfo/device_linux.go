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

// DeviceNumber returns the major:minor of the block device at path.
//
// Symlinks are followed, deliberately: /dev/<vg>/<lv> and
// /dev/mapper/<vg>-<lv> are both symlinks to the /dev/dm-N that carries the
// number, and the number is the whole point — it is what makes a mount
// identifiable regardless of which of those names it was mounted under.
//
// A path that is not a block device is refused rather than reported with the
// zero pair, which would match nothing and read as "not mounted".
func DeviceNumber(path string) (uint32, uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, &DeviceError{Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, 0, &DeviceError{Path: path, Err: ErrNotBlockDevice}
	}
	// The conversions are not redundant everywhere they are compiled: Stat_t's
	// Rdev is uint64 on 64-bit Linux and uint32 on 32-bit, while unix.Major and
	// unix.Minor take uint64 on both. Linting only ever sees the 64-bit build,
	// where they look unnecessary; removing them breaks GOARCH=386 and arm.
	//nolint:unconvert // required on 32-bit Linux, where Rdev is uint32
	return unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)), nil
}
