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

// UnregisterProviderForTest removes a provider registration. It lives in
// export_test.go, so it is compiled into the test binary only and is not part
// of the package's API: the registry is deliberately append-only at run time,
// because a provider that could be unregistered mid-flight would let a caller
// pull a backend out from under a running control plane.
//
// Tests need it because RegisterProvider panics on a duplicate name. The
// registry is package-global and outlives an individual test, so a test that
// registers a name and does not clean up makes itself unrepeatable within one
// process — `go test -count=2` would panic on the second pass. Tests pair every
// registration with a t.Cleanup calling this.
func UnregisterProviderForTest(name string) {
	mu.Lock()
	defer mu.Unlock()
	delete(providerRegistry, name)
}
