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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// TestValidateSharedSecret is the check standing where an allowlist cannot.
//
// Every other value in a generated resource file has a shape — a volume name, a
// hostname, an address — and is checked against one. A secret is arbitrary by
// definition, and it goes inside a quoted string in a file drbdadm parses as
// configuration. A secret carrying a quote and a newline would close the
// string, end the statement, and have whatever followed read as DRBD
// directives.
func TestValidateSharedSecret(t *testing.T) {
	ok := []string{
		"s3cr3t-replication-key",
		"a",
		strings.Repeat("x", maxSharedSecretBytes),
		"~!@#$%^&*()_+-=[]{}|;:,.<>/?'`",
	}
	for _, secret := range ok {
		if err := validateSharedSecret([]byte(secret)); err != nil {
			t.Errorf("validateSharedSecret(%q) = %v, want nil", secret, err)
		}
	}

	hostile := map[string]string{
		"empty":                     "",
		"one byte over the limit":   strings.Repeat("x", maxSharedSecretBytes+1),
		"closes the string":         `secret"`,
		"escapes the closing quote": `secret\`,
		"closes and injects":        "x\";\n}\nresource stolen { disk \"/dev/sda\"; }\n#",
		"newline":                   "secret\nmore",
		"carriage return":           "secret\rmore",
		"tab":                       "secret\tmore",
		"NUL":                       "secret\x00more",
		"leading space":             " secret",
		"trailing space":            "secret ",
		"interior space":            "two words",
		"non-ASCII":                 "sécret",
		"DEL":                       "secret\x7f",
	}
	for name, secret := range hostile {
		t.Run(name, func(t *testing.T) {
			err := validateSharedSecret([]byte(secret))
			if err == nil {
				t.Fatalf("validateSharedSecret(%q) = nil, want an error", secret)
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("error is not ErrInvalidArgument: %v", err)
			}
		})
	}
}

// TestResourceFileRejectsAHostileSecret is the same property one level up: the
// rendering refuses rather than producing a file with an injected block, even
// when handed a secret directly.
func TestResourceFileRejectsAHostileSecret(t *testing.T) {
	meta := resourceMeta{Name: testVolume, LV: testVolume, VG: testVG, Minor: 0, Port: 7789}

	for _, secret := range []string{
		"x\";\n}\nresource stolen { disk \"/dev/sda\"; }\n#",
		`ends"here`,
		"newline\ninjected",
		strings.Repeat("x", maxSharedSecretBytes+1),
	} {
		p, _ := newTestProvider(t)
		p.secrets = staticSecretProvider(secret)

		if err := p.writeResourceFile(context.Background(), &meta); err == nil {
			t.Errorf("writeResourceFile accepted the secret %q", secret)
		}
		// And nothing partial was left behind for drbdadm to find.
		if _, err := os.Stat(p.resPath(meta.Name)); !os.IsNotExist(err) {
			t.Errorf("a refused secret left a resource file behind: %v", err)
		}
	}
}

// staticSecretProvider hands out a fixed secret, including ones validation will
// refuse — the point being that the refusal happens inside the borrow rather
// than before it.
func staticSecretProvider(secret string) SecretProvider {
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		enc, err := enclave.NewMemoryEnclaveSized(len(secret))
		if err != nil {
			return nil, err
		}
		if err := enc.WithBytes(func(buf []byte) error {
			copy(buf, secret)
			return nil
		}); err != nil {
			enc.Destroy()
			return nil, err
		}
		return enc, nil
	}
}

// TestFileSecretProviderReadsIntoAnEnclave covers the file-backed path,
// including the trailing newline a text editor leaves behind.
func TestFileSecretProviderReadsIntoAnEnclave(t *testing.T) {
	dir := t.TempDir()

	tests := map[string]struct {
		contents string
		want     string
		wantErr  bool
	}{
		"plain":                {contents: testSecret, want: testSecret},
		"one trailing newline": {contents: testSecret + "\n", want: testSecret},
		"CRLF":                 {contents: testSecret + "\r\n", want: testSecret},
		"empty file":           {contents: "", wantErr: true},
		// Two newlines leave one behind, which validation then refuses rather
		// than trimming: silently stripping whitespace is how two nodes end up
		// with secrets that look identical and are not.
		"two trailing newlines": {contents: testSecret + "\n\n", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatalf("writing the secret file: %v", err)
			}

			p, _ := newTestProvider(t)
			p.secrets = FileSecretProvider(path)

			// The secret is observed where it lands — in the file — because
			// there is no longer any way to obtain it as a value.
			var sink bytes.Buffer
			err := p.writeSharedSecret(context.Background(), testVolume, &sink)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("writeSharedSecret accepted %q", tc.contents)
				}
				return
			}
			if err != nil {
				t.Fatalf("writeSharedSecret: %v", err)
			}
			if got := sink.String(); got != tc.want {
				t.Errorf("secret = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFileSecretProviderRejectsAnOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge")
	if err := os.WriteFile(path, make([]byte, maxSecretFileBytes+1), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := FileSecretProvider(path)(context.Background(), testVolume); err == nil {
		t.Fatal("FileSecretProvider accepted a file over the limit")
	}
}

func TestFileSecretProviderRejectsAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if _, err := FileSecretProvider(path)(context.Background(), testVolume); err == nil {
		t.Fatal("FileSecretProvider accepted a path that does not exist")
	}
}

// TestProvisionWritesAnAuthenticatedResource is the end-to-end shape: the
// generated file authenticates the peer, carries the secret, and is readable
// only by the user that wrote it.
func TestProvisionWritesAnAuthenticatedResource(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())

	res, err := os.ReadFile(p.resPath(testVolume))
	if err != nil {
		t.Fatalf("reading the resource file: %v", err)
	}
	got := string(res)

	for _, want := range []string{
		"cram-hmac-alg " + sharedSecretHash + ";",
		`shared-secret "` + testSecret + `";`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("resource file is missing %q:\n%s", want, got)
		}
	}
	// SHA-256 because it is FIPS-approved; nothing weaker has a compatibility
	// argument in a pair this provider generates both halves of.
	if sharedSecretHash != "sha256" {
		t.Errorf("hmac is %q, want sha256", sharedSecretHash)
	}
	// The file carries a secret, so it is worth what a LUKS key file is worth.
	info, err := os.Stat(p.resPath(testVolume))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("resource file mode = %o, want 600 — it holds the shared secret", perm)
	}
	// Still one resource block with balanced braces: the secret went inside its
	// quotes and nowhere else.
	if n := strings.Count(got, "resource "); n != 1 {
		t.Errorf("resource blocks = %d, want 1:\n%s", n, got)
	}
	if strings.Count(got, "{") != strings.Count(got, "}") {
		t.Errorf("unbalanced braces:\n%s", got)
	}
}

// TestNewRefusesWithoutPeerAuthentication covers the default. A node with no
// way to authenticate its peer is a deployment mistake, and finding out when
// the first volume is created is finding out late.
func TestNewRefusesWithoutPeerAuthentication(t *testing.T) {
	settings := testSettings(t)

	_, err := New(settings, WithRunner(newFakeRunner(t)))
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with no secret = %v, want ErrInvalidArgument", err)
	}
	for _, want := range []string{SettingReplicationSecretFile, SettingAllowUnauthenticatedPeers} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say how to fix it (%q)", err, want)
		}
	}
}

// TestUnauthenticatedRequiresAnExplicitAcknowledgement covers the override: it
// works, and the resource it produces says in the file itself that nothing is
// authenticating the peer.
func TestUnauthenticatedRequiresAnExplicitAcknowledgement(t *testing.T) {
	settings := testSettings(t)
	settings[SettingAllowUnauthenticatedPeers] = "true"

	r := newFakeRunner(t)
	p, err := New(settings, WithRunner(r))
	if err != nil {
		t.Fatalf("New with the acknowledgement: %v", err)
	}
	provision(t, p, r, defaultSpec())

	got := string(mustRead(t, p.resPath(testVolume)))
	if strings.Contains(got, "shared-secret") || strings.Contains(got, "cram-hmac-alg") {
		t.Errorf("an unauthenticated resource claims authentication:\n%s", got)
	}
	if !strings.Contains(got, "NO PEER AUTHENTICATION") {
		t.Errorf("the resource file does not say it is unauthenticated:\n%s", got)
	}
	if !strings.Contains(got, SettingAllowUnauthenticatedPeers) {
		t.Errorf("the resource file does not name the setting that produced it:\n%s", got)
	}
}

// TestSecretAndAcknowledgementContradict keeps a deployment from asserting two
// things about one resource. The secret would win, since it is what gets
// written, so the override would be a line in a config file that is untrue.
func TestSecretAndAcknowledgementContradict(t *testing.T) {
	settings := testSettings(t)
	settings[SettingReplicationSecretFile] = "/etc/go-blockstore/drbd.secret"
	settings[SettingAllowUnauthenticatedPeers] = "true"

	if _, err := New(settings, WithRunner(newFakeRunner(t))); !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with both = %v, want ErrInvalidArgument", err)
	}
}

// TestAllowUnauthenticatedPeersTakesOnlyTrueOrFalse keeps a setting that turns
// off peer authentication from being reached through a permissive parser, where
// an operator would be unsure which spellings count.
func TestAllowUnauthenticatedPeersTakesOnlyTrueOrFalse(t *testing.T) {
	for _, raw := range []string{"yes", "1", "TRUE", "True", "on"} {
		settings := testSettings(t)
		settings[SettingAllowUnauthenticatedPeers] = raw
		if _, err := New(settings, WithRunner(newFakeRunner(t))); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("New with %s=%q = %v, want ErrInvalidArgument", SettingAllowUnauthenticatedPeers, raw, err)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %q: %v", path, err)
	}
	return b
}
