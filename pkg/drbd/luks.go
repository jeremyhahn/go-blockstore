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

package drbd

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// errScope attributes this package's LUKS failures to the drbd provider.
const errScope = "go-blockstore/drbd"

// fsTypeLUKS is what blkid reports for a LUKS container.
const fsTypeLUKS = luks.FSType

// ErrMappingStale is returned when a filesystem would grow into a plaintext mapping smaller than its grown device; Demote and Promote, then retry.
var ErrMappingStale = errors.New("the volume's plaintext mapping is smaller than the device it decrypts")

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes. See internal/luks.KeyProvider for
// the ownership rules, the borrow window and the size bounds.
type KeyProvider = luks.KeyProvider

// FileKeyProvider returns a KeyProvider that reads the passphrase from a file,
// re-reading it on each call so a rotated key file takes effect without
// restarting the process. It is what luks_key_file installs.
func FileKeyProvider(path string) KeyProvider { return luks.FileKeyProvider(errScope, path) }

// StaticKeyProvider returns a KeyProvider holding a fixed passphrase in the given enclave; it takes ownership of stored.
func StaticKeyProvider(stored *enclave.MemoryEnclave) (KeyProvider, error) {
	return luks.StaticKeyProvider(errScope, stored)
}

// WithKeyProvider supplies the LUKS passphrase and overrides luks_key_file; it must not be the replication secret.
func WithKeyProvider(k KeyProvider) Option {
	return func(p *Provider) { p.keyProvider = k }
}

// withLUKSBackend replaces the LUKS2 implementation for tests; unexported because encryption is not a caller seam.
func withLUKSBackend(b luks.Backend) Option {
	return func(p *Provider) { p.luks = b; p.injected.luks = true }
}

// ErrNotUnlocked reports an encrypted volume whose plaintext mapping is not open on this node; Promote opens it.
var ErrNotUnlocked = errors.New("the volume's LUKS container is not open on this node")

// mappingNamespace prefixes a mapping name; the dot separator cannot appear in a resource name, so names stay unambiguous.
func (p *Provider) mappingNamespace() string {
	return luks.ReplicatedMappingPrefix + p.cfg.VG + "."
}

// fsDevice is the device a volume's filesystem lives on: the plaintext mapping when encrypted, else the DRBD device.
func (p *Provider) fsDevice(meta *resourceMeta) string {
	if !p.cfg.Encrypted {
		return devicePath(meta.Minor)
	}
	return p.crypt.CryptPath(meta.Name)
}

// containerIsOpen reports whether this volume's plaintext mapping is open over this volume's DRBD device.
func (p *Provider) containerIsOpen(ctx context.Context, meta *resourceMeta) (bool, error) {
	return p.crypt.IsOpen(ctx, meta.Name, devicePath(meta.Minor))
}

// requireContainerOpen refuses an operation that needs the plaintext device when the container is not open, whatever the role.
func (p *Provider) requireContainerOpen(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if !open {
		return fmt.Errorf("volume %q: promote it on this node to unlock it: %w", meta.Name, ErrNotUnlocked)
	}
	return nil
}

// requireFreshMapping refuses to grow over a plaintext mapping smaller than its device, or whose size cannot be read.
func (p *Provider) requireFreshMapping(ctx context.Context, meta *resourceMeta) error {
	dev := devicePath(meta.Minor)
	size, err := p.crypt.MeasureMapping(ctx, meta.Name, dev)
	if err != nil {
		return err
	}
	if !size.Stale() {
		return nil
	}
	return fmt.Errorf("volume %q: its plaintext mapping %s is %d bytes but the container on %s now holds %d — "+
		"the mapping was sized when Promote opened it and cannot be grown in place. "+
		"Unmount it, Demote, and Promote to reopen it over the device as it is now, then repeat the Resize "+
		"(from a mounted volume it grows online): %w",
		meta.Name, p.fsDevice(meta), size.MappingBytes, dev, size.DataBytes, ErrMappingStale)
}

// openContainer unlocks the LUKS container over the DRBD device from Promote, formatting only a device blkid reports empty.
func (p *Provider) openContainer(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	dev := devicePath(meta.Minor)

	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if open {
		// Already unlocked — a repeated Promote, or a role this node held
		// before the call. Opening again would be an error from
		// device-mapper, and the caller's request is already satisfied.
		return nil
	}

	found, empty, err := p.probeDevice(ctx, dev)
	if err != nil {
		return err
	}
	switch {
	case empty:
		if err := p.crypt.Format(ctx, meta.Name, dev); err != nil {
			return err
		}
	case found == fsTypeLUKS:
		// The container is there: this node is taking over a volume its peer
		// formatted, or its own after a demote.
	default:
		return fmt.Errorf("%w: volume %q is configured encrypted but %s carries %s; "+
			"this provider will not format a container over it",
			common.ErrInvalidArgument, meta.Name, dev, describeSignature(found))
	}

	return p.crypt.Open(ctx, meta.Name, dev)
}

// closeContainer tears down the volume's plaintext mapping before demote, detach or delete; a missing mapping is not an error.
func (p *Provider) closeContainer(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if !open {
		return nil
	}
	return p.crypt.Close(ctx, meta.Name)
}

// describeSignature renders what blkid found on a device, including an unnamed signature.
func describeSignature(fsType string) string {
	if fsType == "" {
		return "a signature this provider does not recognize"
	}
	return "a " + fsType + " filesystem"
}
