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

// Package luks holds the LUKS2 machinery the storage providers share: pinned parameters, the key borrow window and the mapping ownership check.
package luks

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-enclave"
)

// FSType is what blkid reports for a LUKS container.
const FSType = "crypto_LUKS"

// Pinned LUKS2 parameters: go-luks2's defaults are not FIPS-approved.
const (
	// pbkdf is PBKDF2, the only FIPS-approved KDF go-luks2 offers; the input is a high-entropy machine key.
	pbkdf = "pbkdf2"

	// hashAlgo is SHA-512 (FIPS 180-4), used across the header.
	hashAlgo = "sha512"

	// cipher and cipherMode are AES-XTS (aes-xts-plain64).
	cipher     = "aes"
	cipherMode = "xts-plain64"

	// keySizeBits is 512, which XTS splits into AES-256-XTS.
	keySizeBits = 512
)

// HeaderBytes is the 16 MiB a container formatted here reserves before the data: 32768 + 16744448 bytes of keyslots area. Existing containers are read with DataOffset.
const HeaderBytes = 16 << 20

// Mapping name prefixes per provider; neither may be a prefix of the other.
const (
	// MappingPrefix is pkg/local's.
	MappingPrefix = "bs-"

	// ReplicatedMappingPrefix is pkg/drbd's.
	ReplicatedMappingPrefix = "bsr-"
)

// Manager binds a Backend, a KeyProvider and a mapping namespace (built by the provider with a separator its names forbid). errScope names the package errors are attributed to.
type Manager struct {
	backend   Backend
	keys      KeyProvider
	namespace string
	errScope  string
}

// NewManager binds the seams. backend must not be nil; keys may be, for a
// provider that is not configured for encryption — every operation that needs a
// passphrase then refuses with a sentence saying so.
func NewManager(backend Backend, keys KeyProvider, namespace, errScope string) *Manager {
	return &Manager{backend: backend, keys: keys, namespace: namespace, errScope: errScope}
}

// HasKeys reports whether a KeyProvider was configured.
func (m *Manager) HasKeys() bool { return m != nil && m.keys != nil }

// MappingName is the device-mapper name an unlocked volume appears under.
func (m *Manager) MappingName(volID string) string {
	return m.namespace + volID
}

// CryptPath is the device path of an unlocked volume's plaintext mapping.
func (m *Manager) CryptPath(volID string) string {
	return "/dev/mapper/" + m.MappingName(volID)
}

// key fetches the passphrase for a volume as an enclave the caller must
// destroy, failing clearly when the provider was configured for encryption
// without a way to obtain keys.
func (m *Manager) key(ctx context.Context, volID string) (*enclave.MemoryEnclave, error) {
	if m.keys == nil {
		return nil, fmt.Errorf("%s: volume %q is encrypted but no KeyProvider is configured", m.errScope, volID)
	}
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return nil, fmt.Errorf("%s: obtaining key for %q: %w", m.errScope, volID, LockedMemoryError(m.errScope, err))
	}
	if enc == nil || !enc.IsAlive() || enc.Size() == 0 {
		refusal := fmt.Errorf("%s: KeyProvider returned no usable key for %q", m.errScope, volID)
		if destroyErr := enc.Destroy(); destroyErr != nil {
			return nil, errors.Join(refusal, fmt.Errorf("%s: releasing it: %w", m.errScope, destroyErr))
		}
		return nil, refusal
	}
	return enc, nil
}

// withKey lends the volume's passphrase enclave to one operation and destroys it after; op must not destroy or retain it.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key *enclave.MemoryEnclave) error) error {
	enc, err := m.key(ctx, volID)
	if err != nil {
		return err
	}

	opErr := op(enc)
	if destroyErr := enc.Destroy(); destroyErr != nil {
		// A release the kernel refused leaves locked pages behind. It is reported
		// even when the operation failed too: the two are independent failures
		// and neither explains the other.
		return errors.Join(opErr, fmt.Errorf("releasing the key for %q: %w", volID, destroyErr))
	}
	return opErr
}

// Format writes a LUKS2 header with every cryptographic parameter pinned; the PBKDF2 iteration count comes from go-luks2's benchmark.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	err := m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.Format(ctx, device, key)
	})
	if err != nil {
		return fmt.Errorf("%s: formatting LUKS container on %s: %w", m.errScope, device, err)
	}
	return nil
}

// Open unlocks the container and exposes its plaintext mapping.
func (m *Manager) Open(ctx context.Context, volID, device string) error {
	err := m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.Open(ctx, device, m.MappingName(volID), key)
	})
	if err != nil {
		return fmt.Errorf("%s: unlocking %s: %w", m.errScope, device, err)
	}
	return nil
}

// Close tears down the plaintext mapping.
func (m *Manager) Close(ctx context.Context, volID string) error {
	if err := m.backend.Close(ctx, m.MappingName(volID)); err != nil {
		return fmt.Errorf("%s: locking %s: %w", m.errScope, m.MappingName(volID), err)
	}
	return nil
}

// TestPassphrase checks that the key held for volID opens the container on device, without unlocking it.
func (m *Manager) TestPassphrase(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.TestKey(ctx, device, key)
	})
}

// DataOffset reports where a container's data starts, read from its header.
func (m *Manager) DataOffset(ctx context.Context, device string) (int64, error) {
	offset, err := m.backend.DataOffset(ctx, device)
	if err != nil {
		return 0, fmt.Errorf("%s: reading the LUKS header on %s: %w", m.errScope, device, err)
	}
	return offset, nil
}

// IsOpen reports whether the volume's mapping exists and is over backing (compared by major:minor); a foreign mapping under the name is an error.
func (m *Manager) IsOpen(ctx context.Context, volID, backing string) (bool, error) {
	_, open, err := m.ownMapping(ctx, volID, backing)
	return open, err
}

// ownMapping is the lookup IsOpen and MeasureMapping share: the named mapping, refused unless it is over backing.
func (m *Manager) ownMapping(ctx context.Context, volID, backing string) (MappingInfo, bool, error) {
	name := m.MappingName(volID)

	info, exists, err := m.backend.Mapping(ctx, name)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("%s: checking %s: %w", m.errScope, name, err)
	}
	if !exists {
		return MappingInfo{}, false, nil
	}

	want, err := m.backend.Identity(ctx, backing)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("%s: identifying %s: %w", m.errScope, backing, err)
	}
	if info.BackingID != want {
		return MappingInfo{}, false, fmt.Errorf("%s: the device-mapper name %q is in use by a mapping over %s, "+
			"not over this volume's %s; close it or rename it before operating on this volume",
			m.errScope, name, info.Backing, backing)
	}
	return info, true, nil
}

// MappingSize is how an open mapping's length relates to the device it
// decrypts, measured at one instant.
type MappingSize struct {
	// MappingBytes is the plaintext device's length: what the kernel presents,
	// fixed when the mapping was loaded.
	MappingBytes int64

	// DataBytes is the backing device's current size less the data offset.
	DataBytes int64
}

// Stale reports whether the mapping has fallen behind its device: the device
// grew after the mapping was opened, and the plaintext capacity did not follow.
// A filesystem grown "to fit" a stale mapping grows to the OLD size.
func (s MappingSize) Stale() bool { return s.MappingBytes < s.DataBytes }

// MeasureMapping reports how the volume's open mapping relates to the device under it; anything it cannot account for is an error.
func (m *Manager) MeasureMapping(ctx context.Context, volID, backing string) (MappingSize, error) {
	info, open, err := m.ownMapping(ctx, volID, backing)
	if err != nil {
		return MappingSize{}, err
	}
	if !open {
		return MappingSize{}, fmt.Errorf("%s: %s has no open mapping to measure", m.errScope, backing)
	}

	offset, err := m.DataOffset(ctx, backing)
	if err != nil {
		return MappingSize{}, err
	}
	if info.SizeBytes <= 0 {
		return MappingSize{}, fmt.Errorf("%s: the mapping over %s reports a length of %d bytes, which cannot be right",
			m.errScope, backing, info.SizeBytes)
	}
	if info.BackingSizeBytes <= offset {
		return MappingSize{}, fmt.Errorf("%s: %s is %d bytes, which is no larger than its own %d-byte LUKS header",
			m.errScope, backing, info.BackingSizeBytes, offset)
	}
	size := MappingSize{MappingBytes: info.SizeBytes, DataBytes: info.BackingSizeBytes - offset}
	if size.MappingBytes > size.DataBytes {
		return MappingSize{}, fmt.Errorf("%s: the mapping over %s is %d bytes but the device now holds only %d past its header; "+
			"the device shrank under a live mapping and no size can be established for it",
			m.errScope, backing, size.MappingBytes, size.DataBytes)
	}
	return size, nil
}
