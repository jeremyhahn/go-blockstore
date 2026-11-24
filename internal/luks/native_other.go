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

// Native is what the providers get for their LUKS operations on a platform
// that has no device-mapper.
//
// The package compiles everywhere on purpose — it is the always-built backend,
// and a developer on a Mac has to be able to build and vet the tree that
// imports it — but LUKS is a Linux facility end to end: the containers are
// unlocked with device-mapper ioctls, and go-luks2 depends on them
// unconditionally. So every operation refuses rather than pretending, and it
// refuses with common.ErrUnsupported, which is the sentinel for a well-formed
// request this backend cannot serve.
//
// The refusals are not reachable from an ordinary caller on these platforms.
// LVM is Linux-only too, so a provider gets no further than its first lvs; this
// exists so the package builds, and so that anything which does reach it fails
// with a sentence rather than a nil dereference.
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
