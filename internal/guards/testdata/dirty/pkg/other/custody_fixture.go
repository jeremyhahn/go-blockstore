// A fixture, not real code. It exists so the key-material-custody scanner can
// be SHOWN to fire; a scanner that has never once fired is a scanner nobody
// knows is wired up.
//
// There is one violation per SPELLING the scanner distinguishes — each
// key-taking Backend method, each position a borrowed key may not appear in,
// each shape of an exported clear-text seam — so dropping any single check from
// the scanner fails the golden test rather than passing on the strength of the
// others.
//
// luks.Backend is the REAL interface from internal/luks, imported the way a
// provider imports it, so the receiver-type match is proved against the type
// the rule is about and not a stand-in with the same name.

package other

import (
	"context"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-enclave"
)

// Rule 1: a borrow window outside the named ones.

func fixtureBorrow(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func(b []byte) error { return nil })
}

// Rule 2: the key-taking Backend methods, called from outside internal/luks.

func fixtureBackend(ctx context.Context, b luks.Backend, enc *enclave.MemoryEnclave) error {
	if err := b.Format(ctx, "/dev/x", enc); err != nil {
		return err
	}
	if err := b.Open(ctx, "/dev/x", "name", enc); err != nil {
		return err
	}
	return b.TestKey(ctx, "/dev/x", enc)
}

// Rule 3: a borrowed key is argument-only. Each function below puts it in one
// position the rule refuses.

type holder struct{ k []byte }

func fixtureAssign(key []byte) {
	k := key
	_ = k
}

func fixtureLiteral(key []byte) {
	h := holder{k: key}
	_ = h
}

func fixtureAppend(dst, key []byte) []byte {
	return append(dst, key...)
}

func fixtureCopy(dst, key []byte) int {
	return copy(dst, key)
}

func fixtureConvert(key []byte) string {
	return string(key)
}

func fixtureCapture(key []byte) func() int {
	return func() int { return len(key) }
}

func fixtureSlice(key []byte) []byte {
	return key[:4]
}

func fixturePassphrase(passphrase []byte) {
	p := passphrase
	_ = p
}

// Rule 4: key-material-shaped values must not cross a package boundary in the
// clear. Each exported signature below carries one in a different shape.

func UnlockWith(key []byte) error { return nil }

func Unseal(luksKey string) error { return nil }

func FormatWith(passphrase []byte) error { return nil }

func Share(secret []byte) error { return nil }

func Login(username, password string) error { return nil }

func Bearer(token string) error { return nil }

func RootPassword() (rootPassword string) { return "" }

func KeyBytes(luksKeyBytes []byte) error { return nil }

type Unlocker interface {
	Unlock(ctx context.Context, passphrase []byte) error
}

type Holder struct{}

func (Holder) Store(key []byte) error { return nil }

type Callback func(secret string) error
