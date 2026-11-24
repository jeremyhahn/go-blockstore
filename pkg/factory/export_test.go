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

package factory

// UnregisterProviderForTest removes a provider registration; tests pair every registration with it in t.Cleanup.
func UnregisterProviderForTest(name string) {
	mu.Lock()
	defer mu.Unlock()
	delete(providerRegistry, name)
}
