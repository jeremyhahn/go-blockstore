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

import (
	"sync"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// ProviderCreator is a function that creates a volume provider from settings.
type ProviderCreator func(settings map[string]string) (common.VolumeProvider, error)

var (
	mu               sync.RWMutex
	providerRegistry = make(map[string]ProviderCreator)
)

// RegisterProvider registers a provider creator under name, usually from init; it panics on a nil creator or a duplicate name, like database/sql.Register.
func RegisterProvider(name string, creator ProviderCreator) {
	if creator == nil {
		panic("go-blockstore/factory: provider creator is nil: " + name)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := providerRegistry[name]; exists {
		panic("go-blockstore/factory: provider already registered: " + name)
	}
	providerRegistry[name] = creator
}

// NewProvider creates a new volume provider by name. It returns
// common.ErrProviderNotRegistered if no provider is registered under name.
func NewProvider(name string, settings map[string]string) (common.VolumeProvider, error) {
	mu.RLock()
	creator, exists := providerRegistry[name]
	mu.RUnlock()
	if !exists {
		return nil, common.ErrProviderNotRegistered
	}
	return creator(settings)
}

// ListProviders returns the names of all registered providers. The order is
// unspecified and varies between calls; a caller that needs a stable order —
// to print a list, say — sorts the result.
func ListProviders() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		names = append(names, name)
	}
	return names
}

// IsRegistered reports whether a provider is registered under the given name.
func IsRegistered(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, exists := providerRegistry[name]
	return exists
}
