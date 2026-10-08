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

// TestNativeMappingReportsAnAbsentNameAsAbsent is the negative answer luksIsOpen
// is allowed to act on, and the only one. A name nothing has ever opened is not
// an error.
//
// It asks device-mapper, and go-luks2 can only ask through /dev/mapper/control:
// a host without it cannot answer "no such mapping", it answers that it cannot
// be asked, which Mapping rightly reports as an error rather than as absence.
// So the test sits behind the kernel_dm tag, and selecting the tag is the
// statement that this host provides the control node — see make test-kernel-dm.
func TestNativeMappingReportsAnAbsentNameAsAbsent(t *testing.T) {
	info, exists, err := (Native{}).Mapping(context.Background(), "bs-vg0_no-such-volume-"+strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("Mapping: %v", err)
	}
	if exists {
		t.Fatalf("Mapping reported %+v for a name nothing has opened", info)
	}
}
