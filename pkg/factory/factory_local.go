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

// This file carries NO build tag. The local provider is the fundamental
// backend — tagging it would leave a binary built with no tags with no
// providers at all — and it pulls in nothing beyond the standard library, so
// there is nothing to gate. Backends that link kernel tooling or network
// libraries get a tag; this one does not. See the package documentation.

package factory

import (
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/local"
)

func init() {
	RegisterProvider("local", func(settings map[string]string) (common.VolumeProvider, error) {
		provider, err := local.NewFromSettings(settings)
		if err != nil {
			// Returning NewFromSettings' results directly would hand back a nil
			// *local.Provider boxed in a non-nil common.VolumeProvider, so a
			// caller's `if provider != nil` would be true for a construction
			// that failed. The explicit nil keeps the interface value nil.
			return nil, err
		}
		return provider, nil
	})
}
