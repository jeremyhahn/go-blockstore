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

// The ONE test in this repository that needs the cryptsetup binary, behind its
// own build tag.
//
// # Why a tag and not a runtime skip
//
// It had a runtime skip, and conventions/testing-guidelines.md §No Skip Guards
// bars them: a skipped test reports SUCCESS, so the migration gate for every
// pre-2026-08-29 encrypted volume in the fleet was passing on every host that
// happened not to have cryptsetup installed — including, silently, a CI host.
// The whole point of the test is to fail if the migration is unsafe, and a skip
// is the one outcome that cannot.
//
// The convention's prescribed fix is exactly what this is: gate it behind a
// declared build tag whose tier ACTUALLY PROVIDES the dependency. Selecting
// `cryptsetup_compat` is an operator declaring cryptsetup is present, so its
// absence is now a hard failure of a suite that promised to have it rather than
// a quiet pass.
//
//	make integration-test-cryptsetup   # needs root, loop devices AND cryptsetup
//
// It is deliberately NOT in `make integration-test-local`: that suite's
// documented tooling is lvm2, e2fsprogs and util-linux, and cryptsetup is
// specifically NOT among them, because nothing else here shells out to it.
// Folding this in would add a dependency to a suite that advertises it does not
// need one.
//
// Found by internal/guards' no-runtime-skip scanner (#47), which is what that
// scanner exists to do.

package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestIntegrationVolumeFormattedByCryptsetupStillOpens is the MIGRATION GATE
// for the move to go-luks2, and it is the test that decides whether this change
// can be deployed onto a host that already has encrypted volumes.
//
// Every encrypted volume this package provisioned before 2026-08-29 was
// formatted by `cryptsetup luksFormat` with the parameters spelled out below —
// that is the exact argv the previous implementation issued. Those volumes are
// on disk, they hold data, and nothing about this refactor is allowed to make
// them unopenable. So the fixture is not a container this package wrote: it is
// one the PREVIOUS IMPLEMENTATION wrote, reproduced byte-for-byte by running
// the same command.
//
// This is the one place in this suite that legitimately needs cryptsetup, and
// the reason is the thing being tested. A pure-Go fixture is impossible here:
// producing a container "as the old implementation would have" means producing
// a spec-conformant sha512 digest, and go-luks2 cannot — that is precisely the
// defect this test exists to catch (see TestNativeFormatWritesASpecLengthDigest
// and go-luks2 #73). Substituting a go-luks2-formatted container would replace
// the fixture with one that shares the bug, and the test would pass while the
// fleet stayed broken. A host without cryptsetup cannot
// answer the question either way — which is why this test is behind its OWN
// build tag rather than a runtime skip: the tag is a declaration that the tier
// running it provides cryptsetup, so an absent binary is a hard failure of a
// suite that promised to have it, not a quiet pass. See the file header.
//
// EXPECTED TO FAIL against go-luks2 v0.1.7-alpha: Attach reports "incorrect
// passphrase" for the correct passphrase, because go-luks2 derives a 32-byte
// digest and compares it against the 64 bytes cryptsetup stored.
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
