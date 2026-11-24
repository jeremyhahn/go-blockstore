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

//go:build linux && kernel_dm

package luks

import (
	"context"
	"os"
	"strconv"
	"testing"
)

// TestNativeMappingReportsAnAbsentNameAsAbsent needs /dev/mapper/control, so it runs under the kernel_dm tag.
func TestNativeMappingReportsAnAbsentNameAsAbsent(t *testing.T) {
	info, exists, err := (Native{}).Mapping(context.Background(), "bs-vg0_no-such-volume-"+strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("Mapping: %v", err)
	}
	if exists {
		t.Fatalf("Mapping reported %+v for a name nothing has opened", info)
	}
}
