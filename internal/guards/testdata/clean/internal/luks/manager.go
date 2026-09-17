// A fixture proving the key-material-custody scanner does NOT fire on the
// custody model itself: the anchor borrow window, the sanctioned Backend seam,
// and the shapes internal/luks legitimately uses. Every construction here is
// one the real internal/luks uses today.

package luks

import (
	"context"

	"github.com/jeremyhahn/go-enclave"
)

// Backend mirrors the real seam: the three key-taking methods are exempt from
// rule 5 because they ARE the sanctioned boundary, and a scanner that fired on
// the seam it exists to protect would be switched off.
type Backend interface {
	Format(ctx context.Context, device string, key []byte) error
	Open(ctx context.Context, device, name string, key []byte) error
	TestKey(ctx context.Context, device string, key []byte) error
	Close(ctx context.Context, name string) error
}

// Manager stands in for the real one.
type Manager struct {
	keys    func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)
	backend Backend
}

// withKey is the anchor: the one borrow window.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key []byte) error) error {
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()
	return enc.WithBytes(op)
}

// Format calls the key-taking seam from INSIDE internal/luks, which is the one
// package allowed to; the closure declares key itself and passes it straight on.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.Format(ctx, device, key)
	})
}

// Open does the same through Open, and TestPassphrase through TestKey.
func (m *Manager) Open(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.Open(ctx, device, volID, key)
	})
}

// TestPassphrase is exported with a material WORD in its name; rule 5 is about
// parameters and results, not function names.
func (m *Manager) TestPassphrase(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.TestKey(ctx, device, key)
	})
}

// options mirrors go-luks2's FormatOptions: the native backend hands the key
// over inside a struct literal that is itself the call's argument.
type options struct {
	Device     string
	Passphrase []byte
}

func format(options) error { return nil }

// Native mirrors the real backend's Format: the key appears in a composite
// literal, but the literal is built for the call and passed with it, so the key
// does not outlive the call any more than a bare argument would.
type Native struct{}

// Format is the shape native_linux.go has today.
func (Native) Format(ctx context.Context, device string, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) == 0 {
		return nil
	}
	return format(options{Device: device, Passphrase: key})
}

// FileKeyProvider mirrors the real one: a fill borrow that reads a descriptor
// into locked pages. It is one of the named windows.
func FileKeyProvider(scope, keyPath string) func(context.Context, string) (*enclave.MemoryEnclave, error) {
	return func(context.Context, string) (*enclave.MemoryEnclave, error) {
		enc, err := enclave.NewMemoryEnclaveSized(8)
		if err != nil {
			return nil, err
		}
		if err := enc.WithBytes(func(buf []byte) error { return nil }); err != nil {
			enc.Destroy()
			return nil, err
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
				created.Destroy()
				return fillErr
			}
			fresh = created
			return nil
		})
		return fresh, err
	}
}
