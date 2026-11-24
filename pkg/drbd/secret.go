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

// SecretProvider supplies a resource's peer authentication secret as a locked enclave, fresh on each call; both nodes must return the same secret.
// The provider destroys it after writing; the copy in the resource file is not protected.
type SecretProvider func(ctx context.Context, resource string) (*enclave.MemoryEnclave, error)

// FileSecretProvider returns a SecretProvider that reads the file into locked pages on each call, minus one trailing newline.
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

// maxSecretFileBytes bounds what FileSecretProvider will lock.
const maxSecretFileBytes = 4096

// maxSharedSecretBytes is DRBD's limit on a shared secret.
const maxSharedSecretBytes = 64

// validateSharedSecret allows printable ASCII without space, quote or backslash, within DRBD's length limit, so the secret cannot leave its quotes.
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

// trimSecretFileNewline removes one trailing newline only.
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

// writeSharedSecret validates and writes the secret to w from inside the enclave borrow; w must be unbuffered.
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

// sharedSecretHash is the peer-authentication HMAC: SHA-256, FIPS-approved, not configurable.
const sharedSecretHash = "sha256"
