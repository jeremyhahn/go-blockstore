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

//go:build !linux

package mountinfo

// DeviceNumber has no meaning off Linux, where there is no
// /proc/self/mountinfo to match a number against.
//
// The package still compiles everywhere so the providers that import it do too;
// refusing here is what keeps that from becoming a silent zero pair that
// matches nothing and reads as "not mounted".
func DeviceNumber(path string) (uint32, uint32, error) {
	return 0, 0, &DeviceError{Path: path, Err: ErrUnsupportedPlatform}
}
