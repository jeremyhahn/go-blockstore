// A fixture, not real code. It stands in for internal/luks so the
// key-material-custody scanner has its ANCHOR — FileKeyProvider, the one place
// the passphrase's bytes enter the model, with exactly one WithBytes call — and
// so the scanner can be shown to fire on a second borrow planted in the SAME
// package but outside the named windows, which is a different spelling of the
// rule from a borrow in some other package.
//
// The layout mirrors the repository (internal/luks under the fixture root)
// because the rules are stated in terms of that layout: "inside internal/luks"
// is a directory, and a fixture that did not reproduce it could not exercise
// the distinction.

package luks

import (
	"context"

	"github.com/jeremyhahn/go-enclave"
)

// Backend stands in for the real seam: the key travels as an enclave.
type Backend interface {
	Format(ctx context.Context, device string, key *enclave.MemoryEnclave) error
	Open(ctx context.Context, device, name string, key *enclave.MemoryEnclave) error
	TestKey(ctx context.Context, device string, key *enclave.MemoryEnclave) error
}

// Manager stands in for the real one.
type Manager struct {
	keys func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)
}

// withKey lends the enclave for one call and destroys it. It never borrows:
// the passphrase does not become a []byte here or anywhere else in the package.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key *enclave.MemoryEnclave) error) error {
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()
	return op(enc)
}

// peek is a borrow in the package that owns the model. That it is inside
// internal/luks does not make it a window; only the named functions are.
func (m *Manager) peek(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func(b []byte) error { return nil })
}

// Format is a key-taking method whose receiver is NOT the Backend interface,
// so a call to it from another package is not a rule-2 finding — it is here
// so the fixture's own package has something to call.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key *enclave.MemoryEnclave) error { return nil })
}

// FileKeyProvider is the anchor: a fill borrow, with exactly one WithBytes.
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
