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

// No build tag: the local provider is the always-present backend and needs only the standard library.

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
