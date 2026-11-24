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

//go:build local_integration && cryptsetup_compat

// Needs the cryptsetup binary, so it has its own build tag: make integration-test-cryptsetup (root, loop devices, cryptsetup).

package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestIntegrationVolumeFormattedByCryptsetupStillOpens: a container formatted by cryptsetup luksFormat with the old parameters must still open.
func TestIntegrationVolumeFormattedByCryptsetupStillOpens(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	const passphrase = "integration-test-passphrase"
	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, passphrase),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A volume as the pre-go-luks2 code left it: the logical volume sized usable
	// capacity plus a header, and the container formatted by the exact argv
	// luksFormat used to issue.
	run(t, "lvcreate", "--yes", "--name", "legacy",
		"--size", strconv.FormatInt(int64(64<<20)+luksHeaderBytes, 10)+"b",
		"--setautoactivation", "n", vg)
	t.Cleanup(func() { _ = exec.Command("lvremove", "--force", vg+"/legacy").Run() })
	run(t, "lvchange", "--activate", "y", "--yes", vg+"/legacy")

	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(passphrase), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	run(t, "cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--hash", "sha512", "--cipher", "aes-xts-plain64",
		"--key-size", "512", "--key-file", keyFile, p.lvPath("legacy"))
	run(t, "lvchange", "--activate", "n", "--yes", vg+"/legacy")

	// THE assertion. Nothing else in this test matters if this fails.
	info, err := p.Attach(ctx, "legacy", "test-node")
	if err != nil {
		t.Fatalf("Attach could not open a volume the previous implementation formatted: %v\n"+
			"This is the migration break: the passphrase is correct and the container is "+
			"a valid LUKS2 sha512 volume. go-luks2 derives a 32-byte digest and compares it "+
			"against the 64 bytes cryptsetup stored, so it can never match. Every encrypted "+
			"volume already on a host running this library is affected. Upstream: go-luks2 #73.", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, "legacy", "test-node") })

	if info.DevicePath != p.cryptPath("legacy") {
		t.Errorf("DevicePath = %q, want the plaintext mapping %q", info.DevicePath, p.cryptPath("legacy"))
	}

	// And the capacity arithmetic still holds over a container this package did
	// not format, which is the other half of "the fleet keeps working".
	status, err := p.Status(ctx, "legacy")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.SizeBytes < 64<<20 {
		t.Errorf("Status.SizeBytes = %d, below the %d the volume was sized for", status.SizeBytes, 64<<20)
	}
}
