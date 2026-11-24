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

package luks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-enclave"
)

// KeyProvider supplies a volume's LUKS passphrase as a locked enclave, fresh on each call; the provider destroys it after one operation.
// The passphrase must be 8 to 512 bytes, go-luks2's bound.
type KeyProvider func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)

// FileKeyProvider returns a KeyProvider that reads the file into locked pages on each call; trailing newlines are part of the passphrase. scope names the package errors are attributed to.
func FileKeyProvider(scope, path string) KeyProvider {
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		f, err := os.Open(path) // #nosec G304 -- path is operator configuration, not caller input
		if err != nil {
			return nil, fmt.Errorf("%s: reading LUKS key file: %w", scope, err)
		}
		defer func() { _ = f.Close() }()

		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("%s: sizing LUKS key file: %w", scope, err)
		}
		size := info.Size()
		if size <= 0 {
			return nil, fmt.Errorf("%s: LUKS key file is empty", scope)
		}
		if size > MaxKeyFileBytes {
			return nil, fmt.Errorf("%s: LUKS key file is %d bytes, over the %d-byte limit", scope, size, MaxKeyFileBytes)
		}

		enc, err := enclave.NewMemoryEnclaveSized(int(size))
		if err != nil {
			return nil, LockedMemoryError(scope, err)
		}

		// The read happens inside the borrow, straight into the locked pages.
		if err := enc.WithBytes(func(buf []byte) error {
			if _, readErr := io.ReadFull(f, buf); readErr != nil {
				return fmt.Errorf("%s: reading LUKS key file: %w", scope, readErr)
			}
			return nil
		}); err != nil {
			return nil, errors.Join(err, enc.Destroy())
		}
		return enc, nil
	}
}

// MaxKeyFileBytes bounds what FileKeyProvider will lock.
const MaxKeyFileBytes = 1 << 20

// StaticKeyProvider returns a KeyProvider holding stored, which it takes ownership of, and hands out locked copies; for tests and single-key deployments.
func StaticKeyProvider(scope string, stored *enclave.MemoryEnclave) (KeyProvider, error) {
	if stored == nil || !stored.IsAlive() {
		return nil, fmt.Errorf("%s: StaticKeyProvider needs a live enclave", scope)
	}
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		var fresh *enclave.MemoryEnclave
		err := stored.WithBytes(func(src []byte) error {
			created, createErr := enclave.NewMemoryEnclaveSized(len(src))
			if createErr != nil {
				return LockedMemoryError(scope, createErr)
			}
			if fillErr := created.WithBytes(func(dst []byte) error {
				copy(dst, src)
				return nil
			}); fillErr != nil {
				return errors.Join(fillErr, created.Destroy())
			}
			fresh = created
			return nil
		})
		if err != nil {
			return nil, err
		}
		return fresh, nil
	}, nil
}

// LockedMemoryError explains a refusal to lock pages, usually RLIMIT_MEMLOCK; there is no unprotected fallback.
func LockedMemoryError(scope string, err error) error {
	if errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
		return fmt.Errorf("%s: cannot lock memory for the LUKS passphrase, "+
			"so it will not be held at all: raise RLIMIT_MEMLOCK for this process "+
			"(LimitMEMLOCK= under systemd, ulimit -l in a shell): %w", scope, err)
	}
	return err
}
