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

package toolinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testVersion  = "1.2.3"
	testArtifact = "tool-v1.2.3.linux.tar.gz"
	testMember   = "tool-v1.2.3/tool"
)

var testBinary = []byte("\x7fELF pretend binary")

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// tarball builds a .tar.gz holding one file.
func tarball(t *testing.T, member string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// release serves files under the GitHub release path for owner/tool and counts
// requests.
type release struct {
	server *httptest.Server
	hits   atomic.Int32
}

func newRelease(t *testing.T, files map[string][]byte) *release {
	t.Helper()
	r := &release{}
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		name := strings.TrimPrefix(req.URL.Path, "/owner/tool/releases/download/v"+testVersion+"/")
		content, ok := files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(content)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *release) installer() Installer {
	return Installer{Client: r.server.Client(), BaseURL: r.server.URL + "/", Platform: "linux/amd64"}
}

// pinnedTool is a shellcheck-shaped tool: pinned archive and binary hashes.
func pinnedTool(archive []byte) Tool {
	return Tool{
		Name:        "tool",
		Repo:        "owner/tool",
		Artifacts:   map[string]func(string) string{"linux/amd64": func(string) string { return testArtifact }},
		Member:      func(string) string { return testMember },
		Compression: Gzip,
		Pins:        map[string]Pin{testVersion + ":" + testArtifact: {Archive: sum(archive), Binary: sum(testBinary)}},
	}
}

// fetchedTool is a trivy-shaped tool: checksums published with the release.
func fetchedTool() Tool {
	return Tool{
		Name:          "tool",
		Repo:          "owner/tool",
		Artifacts:     map[string]func(string) string{"linux/amd64": func(string) string { return testArtifact }},
		Member:        func(string) string { return testMember },
		Compression:   Gzip,
		ChecksumsFile: func(string) string { return "checksums.txt" },
	}
}

func TestInstallPinnedThenFastPath(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	dir := filepath.Join(t.TempDir(), "bin")
	var log bytes.Buffer
	in := rel.installer()
	in.Log = &log

	if err := in.Install(context.Background(), pinnedTool(archive), testVersion, dir); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "tool"))
	if err != nil || !bytes.Equal(got, testBinary) {
		t.Fatalf("installed binary = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "tool"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode = %v, %v; want 0755", info.Mode(), err)
	}
	for _, want := range []string{"archive SHA-256 verified", "extracted binary SHA-256 verified", "installed at"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, log.String())
		}
	}

	before := rel.hits.Load()
	log.Reset()
	if err := in.Install(context.Background(), pinnedTool(archive), testVersion, dir); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if rel.hits.Load() != before {
		t.Error("a binary whose bytes hash to the pin was downloaded again")
	}
	if !strings.Contains(log.String(), "already installed") {
		t.Errorf("log = %q", log.String())
	}
}

// TestInstallDoesNotTrustAnImpostor: the fast path is the binary's HASH, not
// its name or its self-reported version.
func TestInstallDoesNotTrustAnImpostor(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rel.installer().Install(context.Background(), pinnedTool(archive), testVersion, dir); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "tool")); !bytes.Equal(got, testBinary) {
		t.Fatalf("the impostor was kept: %q", got)
	}
	if rel.hits.Load() == 0 {
		t.Error("nothing was downloaded")
	}
}

func TestInstallRefusesATamperedArchive(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	tampered := tarball(t, testMember, []byte("evil"))
	rel := newRelease(t, map[string][]byte{testArtifact: tampered})
	dir := t.TempDir()
	err := rel.installer().Install(context.Background(), pinnedTool(archive), testVersion, dir)
	var mismatch *ChecksumError
	if !errors.As(err, &mismatch) || mismatch.File != testArtifact {
		t.Fatalf("Install = %v, want a ChecksumError for the archive", err)
	}
	if !strings.Contains(err.Error(), "CHECKSUM MISMATCH") {
		t.Errorf("error = %q", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "tool")); statErr == nil {
		t.Error("a tampered archive installed something")
	}
}

func TestInstallRefusesABinaryThatDisagreesWithItsPin(t *testing.T) {
	archive := tarball(t, testMember, []byte("other bytes"))
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	tool := pinnedTool(archive)
	err := rel.installer().Install(context.Background(), tool, testVersion, t.TempDir())
	var mismatch *ChecksumError
	if !errors.As(err, &mismatch) || mismatch.File != testMember {
		t.Fatalf("Install = %v, want a ChecksumError for the extracted binary", err)
	}
}

func TestInstallRefusesWhatIsNotPinned(t *testing.T) {
	rel := newRelease(t, nil)
	in := rel.installer()
	tool := pinnedTool(nil)

	var noPin *NoPinError
	if err := in.Install(context.Background(), tool, "9.9.9", t.TempDir()); !errors.As(err, &noPin) {
		t.Fatalf("unpinned version = %v, want NoPinError", err)
	}
	var version *VersionError
	for _, bad := range []string{"", "latest", "1.2", "1.2.3; rm -rf /", " 1.2.3", "v1.2.3"} {
		if err := in.Install(context.Background(), tool, bad, t.TempDir()); !errors.As(err, &version) {
			t.Errorf("version %q = %v, want VersionError", bad, err)
		}
	}
	var platform *PlatformError
	in.Platform = "plan9/mips"
	if err := in.Install(context.Background(), tool, testVersion, t.TempDir()); !errors.As(err, &platform) {
		t.Fatalf("unknown platform = %v, want PlatformError", err)
	}
	if rel.hits.Load() != 0 {
		t.Error("a refused install touched the network")
	}
	for _, err := range []error{noPin, version, platform} {
		if err.Error() == "" {
			t.Error("empty error text")
		}
	}
}

func TestInstallWithPublishedChecksums(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	cases := map[string]struct {
		list    string
		wantErr bool
	}{
		"exact line":         {list: sum(archive) + "  " + testArtifact + "\n" + strings.Repeat("0", 64) + "  other.tar.gz\n"},
		"binary-mode marker": {list: sum(archive) + " *" + testArtifact + "\n"},
		"missing":            {list: strings.Repeat("0", 64) + "  other.tar.gz\n", wantErr: true},
		"a longer name only": {list: sum(archive) + "  " + testArtifact + ".sig\n", wantErr: true},
		"listed twice":       {list: sum(archive) + "  " + testArtifact + "\n" + sum(archive) + "  " + testArtifact + "\n", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rel := newRelease(t, map[string][]byte{testArtifact: archive, "checksums.txt": []byte(tc.list)})
			dir := t.TempDir()
			err := rel.installer().Install(context.Background(), fetchedTool(), testVersion, dir)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Install: %v", err)
				}
				return
			}
			var listErr *ChecksumListError
			if !errors.As(err, &listErr) || listErr.Error() == "" {
				t.Fatalf("Install = %v, want a ChecksumListError", err)
			}
		})
	}
}

func TestInstallSurfacesDownloadFailures(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	var status *HTTPStatusError
	var install *InstallError

	rel := newRelease(t, nil)
	err := rel.installer().Install(context.Background(), fetchedTool(), testVersion, t.TempDir())
	if !errors.As(err, &install) || !errors.As(err, &status) || !strings.Contains(err.Error(), "checksums") {
		t.Fatalf("missing checksums = %v, want an InstallError wrapping an HTTPStatusError", err)
	}
	err = rel.installer().Install(context.Background(), pinnedTool(archive), testVersion, t.TempDir())
	if !errors.As(err, &status) || !strings.Contains(err.Error(), testArtifact) {
		t.Fatalf("missing archive = %v, want an HTTPStatusError", err)
	}

	in := rel.installer()
	in.BaseURL = "://not a url"
	if err := in.Install(context.Background(), pinnedTool(archive), testVersion, t.TempDir()); !errors.As(err, &install) {
		t.Fatalf("bad base URL = %v, want an InstallError", err)
	}
	in = rel.installer()
	in.Client = &http.Client{} // does not trust the test server's certificate
	if err := in.Install(context.Background(), pinnedTool(archive), testVersion, t.TempDir()); !errors.As(err, &install) {
		t.Fatalf("untrusted TLS = %v, want an InstallError", err)
	}
}

func TestInstallSurfacesAnExtractionFailure(t *testing.T) {
	garbage := []byte("this is not a tarball")
	rel := newRelease(t, map[string][]byte{testArtifact: garbage})
	err := rel.installer().Install(context.Background(), pinnedTool(garbage), testVersion, t.TempDir())
	var extract *ExtractError
	if !errors.As(err, &extract) || !strings.Contains(err.Error(), "tar") {
		t.Fatalf("Install over garbage = %v, want an ExtractError", err)
	}
}

// TestInstallPassesTheCompressionToTheExtractor covers the .xz path without
// needing xz on the test host: the extractor is handed the flag tar needs.
func TestInstallPassesTheCompressionToTheExtractor(t *testing.T) {
	archive := []byte("an xz archive")
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	tool := pinnedTool(archive)
	tool.Compression = XZ
	in := rel.installer()
	var got Compression
	in.Extract = func(_ context.Context, _, dir, member string, compression Compression) error {
		got = compression
		path := filepath.Join(dir, filepath.FromSlash(member))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, testBinary, 0o600)
	}
	if err := in.Install(context.Background(), tool, testVersion, t.TempDir()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got != XZ {
		t.Fatalf("extractor got compression %q, want %q", got, XZ)
	}

	in.Extract = func(context.Context, string, string, string, Compression) error { return nil }
	var install *InstallError
	if err := in.Install(context.Background(), tool, testVersion, t.TempDir()); !errors.As(err, &install) {
		t.Fatalf("an extractor that produced nothing = %v, want an InstallError", err)
	}
}

func TestInstallIntoAnUnwritableDirectory(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var install *InstallError
	err := rel.installer().Install(context.Background(), pinnedTool(archive), testVersion, filepath.Join(file, "bin"))
	if !errors.As(err, &install) || !strings.Contains(install.Step, "installing") {
		t.Fatalf("Install under a file = %v, want an InstallError at the install step", err)
	}
}

func TestInstallPlaceOverADirectoryFails(t *testing.T) {
	archive := tarball(t, testMember, testBinary)
	rel := newRelease(t, map[string][]byte{testArtifact: archive})
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tool", "occupied"), 0o750); err != nil {
		t.Fatal(err)
	}
	var install *InstallError
	if err := rel.installer().Install(context.Background(), pinnedTool(archive), testVersion, dir); !errors.As(err, &install) {
		t.Fatalf("Install over a directory = %v, want an InstallError", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("a failed install left %s behind", e.Name())
		}
	}
}

// TestDefaultClientRefusesARedirectOffHTTPS: the release host redirects to
// its object store, and that hop must stay on https.
func TestDefaultClientRefusesARedirectOffHTTPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://"+req.Host+"/elsewhere", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	in := Installer{BaseURL: server.URL, Platform: "linux/amd64"}
	var redirect *RedirectError
	err := in.Install(context.Background(), pinnedTool(tarball(t, testMember, testBinary)), testVersion, t.TempDir())
	if !errors.As(err, &redirect) || !strings.Contains(redirect.Error(), "/elsewhere") {
		t.Fatalf("Install through an http redirect = %v, want a RedirectError", err)
	}
}

func TestDefaultClientStopsARedirectLoop(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, req.URL.Path+"x", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := Installer{}.client()
	client.Transport = server.Client().Transport
	in := Installer{Client: client, BaseURL: server.URL, Platform: "linux/amd64"}
	var redirect *RedirectError
	err := in.Install(context.Background(), pinnedTool(tarball(t, testMember, testBinary)), testVersion, t.TempDir())
	if !errors.As(err, &redirect) {
		t.Fatalf("Install through a redirect loop = %v, want a RedirectError", err)
	}
}

func TestReadVersionFile(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "v")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if v, err := ReadVersionFile(write("  0.74.0\n")); err != nil || v != "0.74.0" {
		t.Fatalf("ReadVersionFile = %q, %v", v, err)
	}
	var fileErr *VersionFileError
	for _, bad := range []string{"", " \n\t", "0.74 .0\n", "0.74.0\n0.75.0\n"} {
		if _, err := ReadVersionFile(write(bad)); !errors.As(err, &fileErr) || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("ReadVersionFile(%q) = %v, want a VersionFileError", bad, err)
		}
	}
	_, err := ReadVersionFile(filepath.Join(dir, "absent"))
	if !errors.As(err, &fileErr) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file = %v, want a VersionFileError wrapping ErrNotExist", err)
	}
}

// TestShippedToolTables keeps the real tables honest: every supported
// platform has an artifact, and every shellcheck artifact at the pinned
// version has both hashes.
func TestShippedToolTables(t *testing.T) {
	sc := Shellcheck()
	for platform, artifact := range sc.Artifacts {
		pin, ok := sc.Pins[ShellcheckVersion+":"+artifact(ShellcheckVersion)]
		if !ok || len(pin.Archive) != 64 || len(pin.Binary) != 64 {
			t.Errorf("shellcheck %s on %s has no complete pin", ShellcheckVersion, platform)
		}
	}
	if got := sc.Member(ShellcheckVersion); got != "shellcheck-v0.10.0/shellcheck" {
		t.Errorf("shellcheck member = %q", got)
	}
	tv := Trivy()
	if tv.Pins != nil || tv.ChecksumsFile("0.74.0") != "trivy_0.74.0_checksums.txt" || tv.Member("0.74.0") != "trivy" {
		t.Errorf("trivy table is not the fetched-checksums shape")
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		if sc.Artifacts[platform] == nil || tv.Artifacts[platform] == nil {
			t.Errorf("%s is not supported by both tools", platform)
		}
	}
	if tv.Artifacts["linux/amd64"]("0.74.0") != "trivy_0.74.0_Linux-64bit.tar.gz" ||
		tv.Artifacts["linux/arm64"]("0.74.0") != "trivy_0.74.0_Linux-ARM64.tar.gz" {
		t.Error("trivy artifact names changed")
	}
}

func TestErrorTexts(t *testing.T) {
	inner := errors.New("inner")
	for _, err := range []error{
		&HTTPStatusError{URL: "u", Status: "404"},
		&ExtractError{Err: inner},
		&InstallError{Tool: "t", Step: "s", Err: inner},
		&VersionFileError{Path: "p", Err: inner},
	} {
		if err.Error() == "" {
			t.Errorf("%T has no text", err)
		}
	}
	if !errors.Is(&ExtractError{Err: inner}, inner) || !errors.Is(&InstallError{Err: inner}, inner) {
		t.Error("wrapping errors do not unwrap")
	}
}
