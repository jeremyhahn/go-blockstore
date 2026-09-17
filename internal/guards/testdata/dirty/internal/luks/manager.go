// A fixture, not real code. It stands in for internal/luks so the
// key-material-custody scanner has its ANCHOR — the one sanctioned borrow
// window, (*Manager).withKey, with exactly one WithBytes call — and so the
// scanner can be shown to fire on a second borrow planted in the SAME package
// but outside that window, which is a different spelling of the rule from a
// borrow in some other package.
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

// Manager stands in for the real one.
type Manager struct {
	keys func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)
}

// withKey is the anchor: the one place the passphrase becomes a []byte.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key []byte) error) error {
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()
	return enc.WithBytes(op)
}

// peek is a second borrow window in the package that owns the first. That
// it is inside internal/luks does not make it a window; withKey is the window.
func (m *Manager) peek(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func(b []byte) error { return nil })
}

// Format is a key-taking method whose receiver is NOT the Backend interface,
// so a call to it from another package is not a rule-3 finding — it is here
// so the fixture's own package has something to call.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key []byte) error { return nil })
}
