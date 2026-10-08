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

// Package luktest reads and rewrites the JSON metadata of a LUKS2 container, for
// tests that assert on what is ON DISK rather than on what a library reports.
//
// It exists because go-luks2 has no API that writes a header it did not build
// itself, and two suites need exactly that: the unit suite checks the shapes
// DataOffset must refuse, and the integration suite builds a container whose
// data starts somewhere this package never would have put it. Neither shape can
// be produced by formatting.
//
// Nothing here is for production code. It is a package of its own, instead of a
// helper in a _test file, because the two suites live in different packages.
package luktest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

const (
	// binaryHeaderLen is the fixed-size binary header that precedes the JSON
	// area in each of the two header copies.
	binaryHeaderLen = 4096

	// checksumOffset and checksumLen locate the header checksum inside the
	// binary header. It covers the whole header copy with these bytes zeroed.
	checksumOffset = 448
	checksumLen    = 64
)

// Metadata is the part of a LUKS2 JSON area the tests assert on. It is parsed
// from the bytes on disk rather than taken from go-luks2's Header, which is a
// typed view: the point of a conformance check is what was WRITTEN, and a view
// that normalizes (a digest it does not expose, a hash it renders as a
// crypto.Hash) cannot show a malformed spelling.
type Metadata struct {
	Keyslots map[string]Keyslot `json:"keyslots"`
	Segments map[string]Segment `json:"segments"`
	Digests  map[string]Digest  `json:"digests"`
	Config   struct {
		KeyslotsSize string `json:"keyslots_size"`
	} `json:"config"`
}

// Keyslot is one entry of the keyslots object.
type Keyslot struct {
	KeySize int `json:"key_size"`
	Area    struct {
		Encryption string `json:"encryption"`
		Offset     string `json:"offset"`
	} `json:"area"`
	KDF struct {
		Type       string `json:"type"`
		Hash       string `json:"hash"`
		Iterations *int   `json:"iterations"`
	} `json:"kdf"`
	AF struct {
		Hash string `json:"hash"`
	} `json:"af"`
}

// Segment is one entry of the segments object. Offset is the decimal string
// LUKS2 stores, unparsed: a test about a malformed offset has to see it as such.
type Segment struct {
	Offset     string `json:"offset"`
	Encryption string `json:"encryption"`
	SectorSize int    `json:"sector_size"`
}

// Digest is one entry of the digests object.
type Digest struct {
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	Digest     string `json:"digest"`
}

// maxHeaderSize bounds a declared header size. A header is at most a few hundred
// KiB; anything past this is not one.
const maxHeaderSize = 4 << 20

// declaredHeaderSize decodes hdr_size, the big-endian u64 at byte 8 of the
// binary header, and refuses a value that cannot be a LUKS2 header size. The
// bound is what makes the narrowing to int safe.
func declaredHeaderSize(field []byte) (int, error) {
	size := binary.BigEndian.Uint64(field)
	if size < binaryHeaderLen || size > maxHeaderSize {
		return 0, fmt.Errorf("the header declares %d bytes, not a LUKS2 header size", size)
	}
	return int(size), nil
}

// JSONArea returns the JSON metadata that follows the binary header at
// headerOffset in raw, trimmed at its NUL padding.
func JSONArea(raw []byte, headerOffset int) ([]byte, error) {
	// hdr_size covers the binary header plus the JSON area.
	if len(raw) < headerOffset+binaryHeaderLen {
		return nil, fmt.Errorf("the container is %d bytes, too small to hold a header", len(raw))
	}
	headerSize, err := declaredHeaderSize(raw[headerOffset+8 : headerOffset+16])
	if err != nil {
		return nil, err
	}
	end := headerOffset + headerSize
	if end > len(raw) {
		return nil, fmt.Errorf("the header declares %d bytes, past the end of a %d-byte container",
			headerSize, len(raw))
	}
	area := raw[headerOffset+binaryHeaderLen : end]
	if nul := bytes.IndexByte(area, 0); nul >= 0 {
		area = area[:nul]
	}
	return area, nil
}

// headers reads both header copies from the start of f. f may be a block device
// far larger than a header, so nothing past the second copy is read.
func headers(tb testing.TB, f *os.File) (raw []byte, headerSize int) {
	tb.Helper()

	first := make([]byte, binaryHeaderLen)
	if _, err := f.ReadAt(first, 0); err != nil {
		tb.Fatalf("reading the binary header of %s: %v", f.Name(), err)
	}
	headerSize, err := declaredHeaderSize(first[8:16])
	if err != nil {
		tb.Fatalf("%s: %v", f.Name(), err)
	}

	raw = make([]byte, 2*headerSize)
	if _, err := f.ReadAt(raw, 0); err != nil {
		tb.Fatalf("reading the header copies of %s: %v", f.Name(), err)
	}
	return raw, headerSize
}

// Read parses the primary header's JSON area of the container at device.
func Read(tb testing.TB, device string) Metadata {
	tb.Helper()

	f, err := os.Open(device) // #nosec G304 -- a test's own container
	if err != nil {
		tb.Fatalf("opening the container: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw, _ := headers(tb, f)
	area, err := JSONArea(raw, 0)
	if err != nil {
		tb.Fatalf("reading the JSON area on %s: %v", device, err)
	}
	var metadata Metadata
	if unmarshalErr := json.Unmarshal(area, &metadata); unmarshalErr != nil {
		tb.Fatalf("parsing the JSON area on %s: %v", device, unmarshalErr)
	}
	return metadata
}

// SetSegmentOffset overwrites the data offset of segment 0 in a decoded JSON
// area, as Rewrite's edit callback sees it. It reports a JSON area with no
// segment 0 rather than panicking on it.
func SetSegmentOffset(metadata map[string]any, offset string) error {
	segments, ok := metadata["segments"].(map[string]any)
	if !ok {
		return errors.New("the JSON area has no segments table")
	}
	segment, ok := segments["0"].(map[string]any)
	if !ok {
		return errors.New("the JSON area has no segment 0")
	}
	segment["offset"] = offset
	return nil
}

// SetKeyslotsSize overwrites config.keyslots_size in a decoded JSON area. The
// area of keyslots is everything between the two header copies and the data, so
// a rewrite that moves the data has to move it too, or the header contradicts
// itself and go-luks2 refuses it.
func SetKeyslotsSize(metadata map[string]any, size string) error {
	config, ok := metadata["config"].(map[string]any)
	if !ok {
		return errors.New("the JSON area has no config table")
	}
	config["keyslots_size"] = size
	return nil
}

// Rewrite applies edit to the JSON area of the container at device and writes
// the result back to BOTH header copies with their checksums recomputed.
//
// Re-checksumming is what keeps the result honest: a header whose checksum no
// longer matches is refused for that, and a test would pass without ever
// reaching the branch it names. What comes back is a header the code under test
// genuinely has to cope with, not a mangled file.
//
// Only the two header copies are written, so device may be a block device.
func Rewrite(tb testing.TB, device string, edit func(map[string]any) error) {
	tb.Helper()

	f, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- a test's own container
	if err != nil {
		tb.Fatalf("opening the container: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw, headerSize := headers(tb, f)
	area, err := JSONArea(raw, 0)
	if err != nil {
		tb.Fatalf("reading the JSON area on %s: %v", device, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(area))
	decoder.UseNumber()
	var metadata map[string]any
	if decodeErr := decoder.Decode(&metadata); decodeErr != nil {
		tb.Fatalf("parsing the JSON area on %s: %v", device, decodeErr)
	}
	if editErr := edit(metadata); editErr != nil {
		tb.Fatalf("editing the JSON area on %s: %v", device, editErr)
	}
	edited, err := json.Marshal(metadata)
	if err != nil {
		tb.Fatalf("encoding the JSON area: %v", err)
	}
	if binaryHeaderLen+len(edited) >= headerSize {
		tb.Fatalf("the edited JSON area is %d bytes, which no longer fits the %d-byte header",
			len(edited), headerSize)
	}

	// Both copies share the same JSON and differ only in hdr_offset, which the
	// binary header already carries, so each is patched in place.
	for _, base := range []int{0, headerSize} {
		header := raw[base : base+headerSize]
		clear(header[binaryHeaderLen:])
		copy(header[binaryHeaderLen:], edited)
		clear(header[checksumOffset : checksumOffset+checksumLen])
		sum := sha256.Sum256(header)
		copy(header[checksumOffset:], sum[:])
	}

	if _, writeErr := f.WriteAt(raw, 0); writeErr != nil {
		tb.Fatalf("writing the header copies back to %s: %v", device, writeErr)
	}
	if syncErr := f.Sync(); syncErr != nil {
		tb.Fatalf("flushing %s: %v", device, syncErr)
	}
}
