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

package blkdev

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// System is the Operator the providers get by default, so a wrapper that
// delegated to the wrong function — or to nothing — would take the real block
// devices with it while every test of the package functions stayed green.

func TestSystemCopyDelegates(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	content := []byte("go-blockstore")
	writeFile(t, src, content)
	writeFile(t, dst, make([]byte, len(content)))

	if err := (System{}).Copy(context.Background(), src, dst); err != nil {
		t.Fatalf("System.Copy: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("System.Copy wrote %q, want %q", got, content)
	}
}

func TestSystemCopyReportsFailure(t *testing.T) {
	dir := t.TempDir()
	err := (System{}).Copy(context.Background(), filepath.Join(dir, "absent"), filepath.Join(dir, "dst"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("System.Copy = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestSystemZeroOutDelegates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular")
	writeFile(t, path, make([]byte, 4096))

	// A regular file is not a block device, which is the refusal the package
	// function makes and the wrapper has to carry through unchanged.
	if err := (System{}).ZeroOut(context.Background(), path, 0); !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("System.ZeroOut = %v, want ErrNotBlockDevice", err)
	}
	if err := (System{}).ZeroOut(context.Background(), path, -1); !errors.Is(err, ErrNegativeOffset) {
		t.Fatalf("System.ZeroOut with a negative offset = %v, want ErrNegativeOffset", err)
	}
}
