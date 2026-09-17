// A fixture proving the key-material-custody scanner does NOT fire on the
// near-misses a textual scanner would report: a method called Open on a type
// that is not the enclave, os.Open, a WithBytes on some other type, a
// parameter called keyPath, and the borrowed-key positions the rule allows.

package other

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-enclave"
)

// vault has the enclave's method NAMES and signatures and is not the enclave.
type vault struct{}

func (vault) Open() ([]byte, error)                 { return nil, nil }
func (vault) OpenString() (string, error)           { return "", nil }
func (vault) WithBytes(fn func([]byte) error) error { return fn(nil) }

// backend has the seam's method NAMES and is not luks.Backend. Its parameter
// is called buf rather than key on purpose: an exported method in this package
// taking `key []byte` WOULD be a rule-5 finding, and rightly, because it is
// not the seam.
type backend struct{}

func (backend) Format(ctx context.Context, device string, buf []byte) error { return nil }
func (backend) Open(ctx context.Context, device, name string, buf []byte) error {
	return nil
}
func (backend) TestKey(ctx context.Context, device string, buf []byte) error { return nil }

func fixtureNotTheEnclave(ctx context.Context) error {
	v := vault{}
	if _, err := v.Open(); err != nil {
		return err
	}
	if _, err := v.OpenString(); err != nil {
		return err
	}
	if err := v.WithBytes(func([]byte) error { return nil }); err != nil {
		return err
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	b := backend{}
	if err := b.Format(ctx, "/dev/x", nil); err != nil {
		return err
	}
	if err := b.Open(ctx, "/dev/x", "name", nil); err != nil {
		return err
	}
	return b.TestKey(ctx, "/dev/x", nil)
}

// The enclave's NON-copying accessors are fine: they answer questions about the
// enclave without handing its contents back.
func fixtureEnclaveQueries(enc *enclave.MemoryEnclave) bool {
	return enc.IsAlive() && enc.Size() > 0
}

// use stands in for go-luks2: a callee the key is handed straight to.
func use(key []byte) error { return nil }

// fixtureArgumentOnly uses a borrowed key in every position rule 4 allows:
// straight into a call, into len, and inside a closure that declares key as
// its OWN parameter.
func fixtureArgumentOnly(ctx context.Context, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	if err := use(key); err != nil {
		return err
	}
	inner := func(key []byte) error { return use(key) }
	return inner(key)
}

// fixtureImmediateClosure captures key in a closure that is invoked on the spot,
// which cannot outlive the call.
func fixtureImmediateClosure(key []byte) error {
	return func() error { return use(key) }()
}

// A []byte that is not called key or passphrase is not a borrowed key, and a
// string called key is a map key, not material.
func fixtureOtherNames(buf []byte, key string) []byte {
	out := append([]byte(nil), buf...)
	_ = key
	return out
}

// Exported signatures whose parameter names carry a material WORD but name a
// path, a file or an identifier — the refinement rule 5 makes, so that the
// scanner fires on material and not on the name of the file holding it.
func WithKeyFile(keyPath string) error         { return nil }
func WithLUKSKeyFile(luksKeyFile string) error { return nil }
func LookupToken(tokenID string) (int, error)  { return 0, nil }
func SecretName(secretName string) error       { return nil }
func KeyLength(key int) error                  { return nil }
func PasswordHash(passwordHash []byte) error   { return nil }
func Keys() []string                           { return nil }

// A bare `key string` is the key of a key/value pair, the way pkg/common's
// Coordinator takes one; the material sense of the word is bytes.
func Lookup(ctx context.Context, key string) ([]byte, error)    { return nil, nil }
func Store(ctx context.Context, key string, value []byte) error { return nil }
func Unlock(ctx context.Context, keys []string)                 { _ = keys }

// unexported, so not a package boundary: rule 5 is about what crosses one.
func unlock(key string, passphrase []byte) error { return nil }

// Enclaves cross the boundary, not bytes — that is the model, and it must
// never be reported.
func Provide(ctx context.Context, key *enclave.MemoryEnclave) error { return nil }
