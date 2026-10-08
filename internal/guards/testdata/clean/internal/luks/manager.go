// A fixture proving the key-material-custody scanner does NOT fire on the
// custody model itself: the anchor borrow window, the Backend seam, and the
// shapes internal/luks legitimately uses. Every construction here is one the
// real internal/luks uses today.

package luks

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-enclave"
)

// Backend mirrors the real seam: the key travels as an enclave, so none of its
// methods carries material in the clear and rule 4 has nothing to say about it.
type Backend interface {
	Format(ctx context.Context, device string, key *enclave.MemoryEnclave) error
	Open(ctx context.Context, device, name string, key *enclave.MemoryEnclave) error
	TestKey(ctx context.Context, device string, key *enclave.MemoryEnclave) error
	Close(ctx context.Context, name string) error
}

// Manager stands in for the real one.
type Manager struct {
	keys    func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)
	backend Backend
}

// withKey lends the enclave for one call and destroys it. It never borrows:
// the passphrase does not become a []byte in this package.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key *enclave.MemoryEnclave) error) error {
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return err
	}
	return errors.Join(op(enc), enc.Destroy())
}

// Format calls the key-taking seam from INSIDE internal/luks, which is the one
// package allowed to; the closure declares key itself and passes it straight on.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.Format(ctx, device, key)
	})
}

// Open does the same through Open, and TestPassphrase through TestKey.
func (m *Manager) Open(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.Open(ctx, device, volID, key)
	})
}

// TestPassphrase is exported with a material WORD in its name; rule 4 is about
// parameters and results, not function names.
func (m *Manager) TestPassphrase(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error {
		return m.backend.TestKey(ctx, device, key)
	})
}

// FileKeyProvider mirrors the real one and is the anchor: a fill borrow that
// reads a descriptor into locked pages, with exactly one WithBytes.
func FileKeyProvider(scope, keyPath string) func(context.Context, string) (*enclave.MemoryEnclave, error) {
	return func(context.Context, string) (*enclave.MemoryEnclave, error) {
		enc, err := enclave.NewMemoryEnclaveSized(8)
		if err != nil {
			return nil, err
		}
		if err := enc.WithBytes(func(buf []byte) error { return nil }); err != nil {
			return nil, errors.Join(err, enc.Destroy())
		}
		return enc, nil
	}
}

// StaticKeyProvider mirrors the real one: a clone borrow, locked pages to
// locked pages.
func StaticKeyProvider(scope string, stored *enclave.MemoryEnclave) func(context.Context, string) (*enclave.MemoryEnclave, error) {
	return func(context.Context, string) (*enclave.MemoryEnclave, error) {
		var fresh *enclave.MemoryEnclave
		err := stored.WithBytes(func(src []byte) error {
			created, createErr := enclave.NewMemoryEnclaveSized(len(src))
			if createErr != nil {
				return createErr
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
		return fresh, err
	}
}
