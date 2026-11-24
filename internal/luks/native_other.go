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

package luks

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-enclave"
)

// Native refuses every operation with common.ErrUnsupported on platforms without device-mapper.
type Native struct{}

// Ensure the backend satisfies the seam at compile time.
var _ Backend = Native{}

// unsupported is the one answer this backend has.
func unsupported(op string) error {
	return fmt.Errorf("%w: LUKS %s needs device-mapper, which this platform does not have",
		common.ErrUnsupported, op)
}

func (Native) Format(context.Context, string, *enclave.MemoryEnclave) error {
	return unsupported("format")
}

func (Native) Open(context.Context, string, string, *enclave.MemoryEnclave) error {
	return unsupported("open")
}

func (Native) Close(context.Context, string) error { return unsupported("close") }

func (Native) TestKey(context.Context, string, *enclave.MemoryEnclave) error {
	return unsupported("passphrase check")
}

func (Native) DataOffset(context.Context, string) (int64, error) {
	return 0, unsupported("header read")
}

func (Native) Mapping(context.Context, string) (MappingInfo, bool, error) {
	return MappingInfo{}, false, unsupported("mapping lookup")
}

func (Native) Identity(context.Context, string) (string, error) {
	return "", unsupported("device identity")
}
