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

//go:build drbd

package factory

import (
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/drbd"
)

// ProviderNameDRBD is the registered name of the DRBD 9 provider.
const ProviderNameDRBD = "drbd"

// Registering here rather than from an init inside pkg/drbd keeps the
// dependency pointing one way — factory imports providers, never the reverse —
// and means a caller gets the provider by importing this package with -tags
// drbd, with no blank import to remember. Without the tag this file does not
// compile, pkg/drbd is an empty package, and nothing DRBD-related is linked in.
func init() {
	RegisterProvider(ProviderNameDRBD, func(settings map[string]string) (common.VolumeProvider, error) {
		provider, err := drbd.New(settings)
		if err != nil {
			// Returning New's results directly would hand back a nil
			// *drbd.Provider boxed in a non-nil common.VolumeProvider, so a
			// caller's `if provider != nil` would be true for a construction
			// that failed. The explicit nil keeps the interface value nil.
			return nil, err
		}
		return provider, nil
	})
}
