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

// Package factory constructs volume providers from configuration.
//
// Providers register themselves by name through RegisterProvider, typically
// from an init function in a build-tag-gated file so that unused backends —
// and the system libraries or kernel tooling they depend on — are not linked
// into a binary that does not need them. Providers are created on demand via
// NewProvider, keeping provider selection decoupled from the rest of the
// library.
//
// The build-tag convention mirrors go-objstore: each provider lives in its own
// file and self-registers in that file's init function, and the gated ones
// carry a build tag named for the backend. The local provider carries NO build
// tag — like go-objstore's local storage it is the fundamental backend, always
// compiled — while backends pulling in kernel tooling or network libraries are
// gated behind one. The provider files take this shape:
//
//	factory_local.go   — no build tag; always compiled, registers "local"
//	factory_drbd.go    — //go:build drbd; registers "drbd"
//	factory_cephrbd.go — //go:build cephrbd; registers "cephrbd"
//
// A tagged file compiles only when its tag is set, which is the whole point: a
// binary built without -tags drbd never links DRBD's dependencies and never
// sees "drbd" from ListProviders. Tagging the local provider would invert that
// and make the default build provider-less.
//
// factory_local.go has landed: importing this package registers "local", backed
// by github.com/jeremyhahn/go-blockstore/pkg/local, in every build.
// factory_drbd.go registers "drbd" whenever the drbd tag is set. The cephrbd
// backend is still to come, so NewProvider returns
// common.ErrProviderNotRegistered for "cephrbd", and for "drbd" in a build
// without the tag.
//
// The HA controller in pkg/ha is deliberately NOT reachable through this
// registry. Providers are mechanical and need no Coordinator; the controller is
// the library's only Coordinator consumer and takes both dependencies
// explicitly, so a Coordinator seam here would put a lease behind a name lookup
// and hand every backend a dependency exactly one caller uses.
//
// # Settings keys
//
// The settings map NewProvider takes is provider-specific, but its KEYS follow
// one convention across every backend: snake_case, mirroring go-objstore
// (access_key_id, secret_access_key, encryption_kms_path). A concept two
// providers share is spelled the same in both — the LVM volume group is
// volume_group in local and in drbd, never vg in one and volume_group in the
// other — so a caller configuring either does not have to remember which
// spelling that one wants.
//
// Providers reject a key they do not recognize rather than ignoring it. A
// mistyped setting that silently does nothing is a configuration bug that
// surfaces much later, as wrong behavior on the node it was meant to fix.
package factory
