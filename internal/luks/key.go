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

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes.
//
// It is called each time a provider formats, unlocks or resizes an encrypted
// volume, always with the volume's ID, so an implementation can hold a distinct
// key per volume.
//
// THE PROVIDER TAKES OWNERSHIP of what it is handed and destroys the enclave as
// soon as the LUKS operation has consumed the passphrase, so every call returns
// a fresh enclave rather than one the implementation intends to reuse. Between
// those two points the passphrase is borrowed for exactly one operation: it
// exists as a []byte only inside a MemoryEnclave.WithBytes callback, which hands
// it to go-luks2 for the length of one call and nothing longer. That borrow is
// narrower than it used to be — the bytes no longer leave the process at all,
// where they were once written to a cryptsetup child's standard input.
//
// The type is an enclave and not a []byte because a []byte cannot be taken back.
// Go's garbage collector may copy a heap slice while it lives, and zeroing the
// slice a caller still holds reaches neither those copies nor anything the
// scheduler moved; the bytes are also swappable and would land in a core dump.
// An enclave's pages are mlock'd, guarded, kept out of core dumps and wiped on
// release, which is the guarantee this package needs and the reason go-enclave
// is a portfolio-wide primitive rather than something restated here.
//
// THE PASSPHRASE MUST BE AT LEAST 8 BYTES AND AT MOST 512. That is go-luks2's
// bound, checked on every format and every unlock, and it is stated here because
// a KeyProvider that returns something shorter fails at the operation rather
// than at configuration time. It is not a constraint on real key material —
// anything a TPM unseals or a key file holds is far longer — but it does reject
// a toy passphrase that a cryptsetup-backed build would have accepted.
//
// This is the whole of a provider's involvement with key management. Where the
// key comes from — a file, an operator prompt, a TPM-sealed blob unsealed by
// go-trusted-platform — is the caller's business, and deliberately so: a
// provider that knew how to talk to a TPM would drag hardware-specific
// dependencies into a library whose other backends have no use for them. The
// caller unseals into an enclave; the provider borrows it and destroys it.
type KeyProvider func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)

// FileKeyProvider returns a KeyProvider that reads the passphrase from a file,
// re-reading it on each call so a rotated key file takes effect without
// restarting the process. Trailing newlines are not stripped: the file's bytes
// are the passphrase, which is what `cryptsetup --key-file` did with a file of
// its own and what any container already formatted that way expects.
//
// The bytes go from the file descriptor into the enclave's locked pages
// directly. There is no intermediate slice to wipe, and therefore none for the
// garbage collector to have copied first — which is what os.ReadFile would have
// left behind.
//
// scope names the package the errors are attributed to, so a refusal reaching an
// operator says which provider was reading the file.
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

// MaxKeyFileBytes bounds what FileKeyProvider will lock. A passphrase is not
// large, locked memory is a rationed resource under RLIMIT_MEMLOCK, and a
// misconfigured path pointing at something enormous should be refused rather
// than have the provider try to mlock it.
const MaxKeyFileBytes = 1 << 20

// StaticKeyProvider returns a KeyProvider backed by a fixed passphrase, held in
// the enclave it is given for the returned provider's lifetime.
//
// It TAKES OWNERSHIP of stored: the caller keeps no reference and does not
// destroy it. Each call hands out a fresh enclave, because the provider destroys
// what it is given, and those copies are made from locked pages into locked
// pages and never exist on the heap.
//
// The parameter is an enclave and not a []byte on purpose. A []byte would put
// the passphrase on the ordinary heap before this function could do anything
// about it, and no amount of wiping afterwards reaches the copies the garbage
// collector or the caller may already have made — the entry point itself was the
// leak, not what happened after it. A caller with raw bytes moves them across
// with enclave.NewMemoryEnclave, which wipes the slice as it takes it, and does
// so at the point where it still knows the bytes are sensitive.
//
// It suits tests and single-key deployments. The passphrase stays in memory for
// as long as the provider lives, which a TPM-backed or prompt-backed
// implementation does not — locked memory is still memory. enclave.WipeAll
// reclaims it at an orderly exit.
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

// LockedMemoryError turns go-enclave's refusal into something an operator can
// act on.
//
// A provider does not fall back to unprotected memory when the kernel will not
// lock pages — that would quietly hand back the exact guarantee this design
// exists to provide — so the refusal has to say what to change. It is almost
// always RLIMIT_MEMLOCK, which is small by default and easy to miss because
// nothing else in the process needs it.
func LockedMemoryError(scope string, err error) error {
	if errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
		return fmt.Errorf("%s: cannot lock memory for the LUKS passphrase, "+
			"so it will not be held at all: raise RLIMIT_MEMLOCK for this process "+
			"(LimitMEMLOCK= under systemd, ulimit -l in a shell): %w", scope, err)
	}
	return err
}
