// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/toolinstall"
)

// offline is an installer whose every download answers 404, so a test can
// reach each exit status without the network.
func offline(t *testing.T) (toolinstall.Installer, *int) {
	t.Helper()
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits++
		http.NotFound(w, req)
	}))
	t.Cleanup(server.Close)
	return toolinstall.Installer{Client: server.Client(), BaseURL: server.URL, Platform: "linux/amd64"}, &hits
}

func TestUsage(t *testing.T) {
	installer, hits := offline(t)
	for _, args := range [][]string{nil, {"shellcheck"}, {"shellcheck", ""}, {"a", "b", "c", "d"}, {"hadolint", "/tmp"}} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut, installer); code != exitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, exitUsage)
		}
		if !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("run(%q) printed no usage: %q", args, errOut.String())
		}
	}
	if *hits != 0 {
		t.Error("a usage error touched the network")
	}
}

func TestShellcheckDefaultsToThePin(t *testing.T) {
	installer, hits := offline(t)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"shellcheck", t.TempDir()}, &out, &errOut, installer); code != exitFailed {
		t.Fatalf("run = %d, want %d (the offline server 404s)", code, exitFailed)
	}
	if !strings.Contains(out.String(), "shellcheck "+toolinstall.ShellcheckVersion) || *hits == 0 {
		t.Errorf("did not attempt the pinned version: %q", out.String())
	}
}

func TestShellcheckRefusesAnUnpinnedVersion(t *testing.T) {
	installer, hits := offline(t)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"shellcheck", t.TempDir(), "0.9.0"}, &out, &errOut, installer); code != exitFailed {
		t.Fatalf("run = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(errOut.String(), "no pinned SHA-256") || *hits != 0 {
		t.Errorf("stderr = %q, hits = %d", errOut.String(), *hits)
	}
}

func TestTrivyReadsTheVersionFileStrictly(t *testing.T) {
	installer, _ := offline(t)
	dir := t.TempDir()
	t.Chdir(dir)

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"trivy", t.TempDir()}, &out, &errOut, installer); code != exitFailed {
		t.Fatalf("run with no %s = %d, want %d", trivyVersionFile, code, exitFailed)
	}

	if err := os.WriteFile(filepath.Join(dir, trivyVersionFile), []byte("0.74 .0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run(context.Background(), []string{"trivy", t.TempDir()}, &out, &errOut, installer); code != exitFailed {
		t.Fatalf("run with a malformed version file = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(errOut.String(), "exactly one") {
		t.Errorf("stderr = %q", errOut.String())
	}

	if err := os.WriteFile(filepath.Join(dir, trivyVersionFile), []byte("0.74.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run(context.Background(), []string{"trivy", t.TempDir()}, &out, &errOut, installer); code != exitFailed {
		t.Fatalf("run = %d, want %d (the offline server 404s)", code, exitFailed)
	}
	if !strings.Contains(out.String(), "trivy 0.74.0") {
		t.Errorf("did not attempt the file's version: %q", out.String())
	}
}

func TestTrivyInstalls(t *testing.T) {
	binary := []byte("trivy binary")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "trivy", Mode: 0o755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	digest := sha256.Sum256(archive)
	base := "/aquasecurity/trivy/releases/download/v0.74.0/"
	files := map[string][]byte{
		base + "trivy_0.74.0_Linux-64bit.tar.gz": archive,
		base + "trivy_0.74.0_checksums.txt":      []byte(hex.EncodeToString(digest[:]) + "  trivy_0.74.0_Linux-64bit.tar.gz\n"),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		content, ok := files[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	installer := toolinstall.Installer{Client: server.Client(), BaseURL: server.URL, Platform: "linux/amd64"}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"trivy", dir, "0.74.0"}, &out, &errOut, installer); code != exitOK {
		t.Fatalf("run = %d, want %d: %s", code, exitOK, errOut.String())
	}
	if got, err := os.ReadFile(filepath.Join(dir, "trivy")); err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("installed = %q, %v", got, err)
	}
}
