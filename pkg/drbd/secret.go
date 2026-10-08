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
	"io"
	"os"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// SecretProvider supplies the shared secret DRBD authenticates a peer with, as
// a locked enclave rather than as bytes.
//
// It is called with the resource name whenever a resource file is generated, so
// an implementation may hold a distinct secret per resource. Both nodes of a
// pair must produce the SAME secret for a resource or they will not
// authenticate, which is a deployment property this package cannot check from
// one side.
//
// The provider TAKES OWNERSHIP of what it is handed and destroys the enclave as
// soon as the secret has been written, so every call returns a fresh enclave
// rather than one the implementation intends to reuse.
//
// The type is an enclave and not a []byte for the reason go-enclave exists: a
// []byte cannot be taken back. Go's collector may copy a heap slice while it
// lives, zeroing the slice a caller still holds reaches neither those copies nor
// anything the scheduler moved, and the bytes are swappable and land in core
// dumps. An enclave's pages are mlock'd, guarded and wiped on release.
//
// WHAT THIS DOES NOT DO, stated plainly because the alternative is implying
// otherwise: it bounds the secret's life in THIS process. It does not protect
// the copy in the resource file. DRBD reads the shared secret from the
// configuration drbdadm parses, so the secret reaches disk by design and no
// amount of care in this process changes that. See the package doc on what the
// .res file is worth.
type SecretProvider func(ctx context.Context, resource string) (*enclave.MemoryEnclave, error)

// FileSecretProvider returns a SecretProvider that reads the secret from a
// file, re-reading it on each call so a rotated file takes effect without
// restarting the process. The file's bytes are the secret, minus trailing
// newline: an operator writing one with a text editor gets a newline they did
// not intend, and unlike a LUKS key file — where the bytes are the passphrase
// and cryptsetup says so — DRBD's shared secret is a string in a config file
// that cannot hold a newline anyway.
//
// The bytes go from the descriptor into locked pages directly, so there is no
// intermediate slice for the collector to have copied first.
func FileSecretProvider(path string) SecretProvider {
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		f, err := os.Open(path) // #nosec G304 -- path is operator configuration, not caller input
		if err != nil {
			return nil, fmt.Errorf("reading the replication secret file: %w", err)
		}
		defer func() { _ = f.Close() }()

		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("sizing the replication secret file: %w", err)
		}
		size := info.Size()
		if size <= 0 {
			return nil, errors.New("the replication secret file is empty")
		}
		if size > maxSecretFileBytes {
			return nil, fmt.Errorf("the replication secret file is %d bytes, over the %d-byte limit", size, maxSecretFileBytes)
		}

		enc, err := enclave.NewMemoryEnclaveSized(int(size))
		if err != nil {
			return nil, fmt.Errorf("locking memory for the replication secret: %w", err)
		}
		if err := enc.WithBytes(func(buf []byte) error {
			if _, readErr := io.ReadFull(f, buf); readErr != nil {
				return fmt.Errorf("reading the replication secret file: %w", readErr)
			}
			return nil
		}); err != nil {
			return nil, errors.Join(err, enc.Destroy())
		}
		return enc, nil
	}
}

// maxSecretFileBytes bounds what FileSecretProvider will lock. DRBD's shared
// secret is at most maxSharedSecretBytes; this is deliberately larger so that a
// file with trailing whitespace still reads and fails validation with a message
// about the secret rather than about the file, while a path pointing at
// something enormous is refused before anything tries to mlock it.
const maxSecretFileBytes = 4096

// maxSharedSecretBytes is DRBD's limit on a shared secret.
const maxSharedSecretBytes = 64

// validateSharedSecret checks a secret against what may appear inside the
// quoted string in a generated resource file.
//
// This is the ONE value in that file that cannot be checked against an
// allowlist of known-good tokens: a volume name, a hostname and an address all
// have shapes, and a secret is arbitrary by definition. It is therefore the one
// value that could break out of its quotes and append configuration of its own
// — a secret containing a quote and a newline would close the string, end the
// statement, and let whatever follows be parsed as DRBD directives.
//
// So the check is on the character set instead: printable ASCII, no space, and
// neither the quote nor the backslash that would end or escape the string. That
// is a real constraint on what an operator may choose, and a documented one; it
// is not a constraint on entropy, since 64 characters from that set is ample for
// an HMAC secret.
func validateSharedSecret(secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("%w: the replication secret is empty", common.ErrInvalidArgument)
	}
	if len(secret) > maxSharedSecretBytes {
		return fmt.Errorf("%w: the replication secret is %d bytes, over DRBD's %d-byte limit",
			common.ErrInvalidArgument, len(secret), maxSharedSecretBytes)
	}
	for i, b := range secret {
		switch {
		case b == '"' || b == '\\':
			return fmt.Errorf("%w: the replication secret contains %q at byte %d, which would end or escape the quoted string it is written into",
				common.ErrInvalidArgument, string(b), i)
		case b < 0x21 || b > 0x7e:
			// Everything outside printable ASCII, space included. A space is
			// legal inside the quotes but invites a secret whose leading or
			// trailing whitespace nobody can see in a config file.
			return fmt.Errorf("%w: the replication secret contains a byte outside printable ASCII (%#02x at byte %d); it is written into a text configuration file drbdadm parses",
				common.ErrInvalidArgument, b, i)
		}
	}
	return nil
}

// trimSecretFileNewline removes the single trailing newline a text editor adds.
//
// Only one, and only at the end: anything else is left for validation to
// reject, because silently stripping whitespace from a secret is how two nodes
// end up with secrets that look identical and are not.
func trimSecretFileNewline(b []byte) []byte {
	b = trimSuffixByte(b, '\n')
	return trimSuffixByte(b, '\r')
}

func trimSuffixByte(b []byte, c byte) []byte {
	if len(b) > 0 && b[len(b)-1] == c {
		return b[:len(b)-1]
	}
	return b
}

// writeSharedSecret writes a resource's shared secret to w, from inside the
// enclave borrow.
//
// The secret never becomes a Go string and is never copied into a buffer this
// package owns. It goes from the enclave's locked pages to the descriptor, and
// the enclave is destroyed on the way out whatever happens. w is the resource
// file itself, unbuffered, so the Write is a syscall against the borrowed
// slice — a buffered writer would put the secret back on the heap and undo the
// point of all of this.
//
// Validation runs here too, against the borrowed BYTES rather than a copy, for
// the same reason.
func (p *Provider) writeSharedSecret(ctx context.Context, resource string, w io.Writer) error {
	if p.secrets == nil {
		return errNoSecretProvider
	}

	enc, err := p.secrets(ctx, resource)
	if err != nil {
		return fmt.Errorf("obtaining the replication secret for %q: %w", resource, err)
	}
	if enc == nil {
		return fmt.Errorf("the secret provider returned no secret for %q", resource)
	}

	borrowErr := enc.WithBytes(func(buf []byte) error {
		secret := trimSecretFileNewline(buf)
		if err := validateSharedSecret(secret); err != nil {
			return err
		}
		if _, writeErr := w.Write(secret); writeErr != nil {
			return fmt.Errorf("writing the replication secret for %q: %w", resource, writeErr)
		}
		return nil
	})
	// A Destroy that fails leaves locked pages holding the secret, which is
	// worth reporting whether or not the write succeeded.
	return errors.Join(borrowErr, enc.Destroy())
}

// errNoSecretProvider marks a provider configured without a way to obtain a
// shared secret. It is internal: callers see it wrapped by the check in
// Provision, which explains what to set.
var errNoSecretProvider = errors.New("no replication secret provider is configured")

// sharedSecretHash is the HMAC DRBD authenticates a peer with.
//
// SHA-256 rather than DRBD's older defaults: it is FIPS-approved, which this
// portfolio's deployments need, and there is no compatibility argument for
// anything weaker in a pair this provider generates both halves of.
//
// It is not configurable. A setting here would be a setting whose only use is
// to choose something worse.
const sharedSecretHash = "sha256"
