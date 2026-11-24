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

// RegisterProvider registers a volume provider creator under the given name.
// It is typically called from a provider's init function.
//
// It panics if creator is nil, or if name is already registered, following the
// convention of database/sql.Register. Registration happens at init time from
// build-tag-gated files, so either is a build-configuration mistake — two files
// claiming one name, or a provider wired up without a constructor — and it is
// discovered on the first line of main rather than as a nil-call panic inside
// NewProvider, or a silently mis-wired backend, much later. Overwriting a
// duplicate instead would make which provider wins depend on package
// initialization order.
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
