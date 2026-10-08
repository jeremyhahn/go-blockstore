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

//go:build linux

package luktest_test

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-blockstore/internal/luks/luktest"
)

// TestRewriteLeavesAHeaderGoLuks2StillAccepts is the property the package is
// worth having for. A rewrite that left a stale checksum would make go-luks2
// refuse every container for that one reason, and every test built on Rewrite
// would then be asserting on the checksum instead of on the shape it names.
func TestRewriteLeavesAHeaderGoLuks2StillAccepts(t *testing.T) {
	const moved = 4 << 20

	ctx := context.Background()
	device := filepath.Join(t.TempDir(), "container.img")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Truncate(device, 32<<20); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	passphrase, err := enclave.NewMemoryEnclave([]byte("correct-horse-battery-staple"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if destroyErr := passphrase.Destroy(); destroyErr != nil {
			t.Errorf("Destroy: %v", destroyErr)
		}
	})

	volume, err := luks2.Open(ctx, device)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	formatErr := volume.Format(ctx, passphrase, luks2.FormatParams{
		Cipher:     "aes-xts-plain64",
		KeySize:    512,
		Hash:       crypto.SHA512,
		SectorSize: 4096,
		KDF:        luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, Iterations: 210000},
	})
	if closeErr := volume.Close(); formatErr != nil || closeErr != nil {
		t.Fatalf("Format = %v, Close = %v", formatErr, closeErr)
	}

	if got := luktest.Read(t, device).Segments["0"].Offset; got == strconv.Itoa(moved) {
		t.Fatalf("the fixture already starts its data at %d, so the rewrite below proves nothing", moved)
	}

	luktest.Rewrite(t, device, func(metadata map[string]any) error {
		if setErr := luktest.SetSegmentOffset(metadata, strconv.Itoa(moved)); setErr != nil {
			return setErr
		}
		// The area of keyslots moves with the data or the header contradicts
		// itself.
		return luktest.SetKeyslotsSize(metadata, strconv.Itoa(moved-2*16384))
	})

	if got := luktest.Read(t, device).Segments["0"].Offset; got != strconv.Itoa(moved) {
		t.Errorf("Read after Rewrite = %q, want %d", got, moved)
	}

	reopened, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open after Rewrite: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	header, err := reopened.Header(ctx)
	if err != nil {
		t.Fatalf("go-luks2 refused the rewritten header: %v", err)
	}
	segments := header.Segments()
	if len(segments) != 1 || segments[0].Offset != moved {
		t.Errorf("go-luks2 reads segments %+v, want one at offset %d", segments, moved)
	}
}

// TestJSONAreaRefusesWhatIsNotAHeader keeps the reader's bounds honest: a short
// buffer and a declared size past the end are errors, not panics.
func TestJSONAreaRefusesWhatIsNotAHeader(t *testing.T) {
	if _, err := luktest.JSONArea(make([]byte, 100), 0); err == nil {
		t.Error("JSONArea accepted a buffer too short to hold a binary header")
	}

	raw := make([]byte, 4096)
	raw[8] = 0x7f // hdr_size becomes a huge number, far past the end of the buffer
	if _, err := luktest.JSONArea(raw, 0); err == nil {
		t.Error("JSONArea accepted a header that declares more bytes than the container has")
	}
}
