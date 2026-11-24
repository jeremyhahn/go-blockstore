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
			// Return an explicit nil so a failed construction is not a non-nil interface.
			return nil, err
		}
		return provider, nil
	})
}
