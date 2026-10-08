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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/internal/mount"
)

// luksBinary is the name the fake records LUKS operations under.
//
// They are not a binary — go-luks2 does the work in this process — but they go
// through the same recorder as the commands that still are, and for the reason a
// second recorder would have destroyed: THE ASSERTIONS THAT MATTER ARE ABOUT
// ORDER ACROSS THE TWO. The container is opened after the promotion; it is
// closed before the demotion; the mapping is gone before the drbdadm down. A
// test cannot check any of that against two lists. pkg/local's fake does the
// same thing for the same reason.
const luksBinary = "luks"

// fakeLUKS is the provider's luks.Backend for the unit suite: it records what
// the provider asked for, keeps just enough state to answer the next question
// consistently, and performs nothing.
type fakeLUKS struct {
	r *fakeRunner

	// open maps a device-mapper name to the device the mapping is over, which
	// is what makes the ownership check in luks.Manager.IsOpen exercisable: a
	// mapping under our name over somebody else's device must be refused, not
	// adopted.
	open map[string]string

	// fail is keyed by operation — "format", "open", "close", "mapping",
	// "identity" — so a test can script exactly one of them into failing.
	fail map[string]error

	// deviceSize is the CURRENT size of each device path, as sysfs would
	// report it; a test grows a device by rescripting it. mappingSize is the
	// length each open mapping was given, captured from deviceSize at the
	// moment Open ran and never updated afterwards — which is precisely the
	// kernel's behavior go-luks2 inherits, and the thing the stale-mapping
	// tests are about: the device moves, the mapping does not.
	deviceSize  map[string]int64
	mappingSize map[string]int64
}

func newFakeLUKS(r *fakeRunner) *fakeLUKS {
	return &fakeLUKS{
		r:           r,
		open:        map[string]string{},
		fail:        map[string]error{},
		deviceSize:  map[string]int64{},
		mappingSize: map[string]int64{},
	}
}

// sized scripts the current size of a device. Rescripting it after a mapping
// was opened over it is how a test grows the replicated device under a live
// mapping.
func (f *fakeLUKS) sized(device string, bytes int64) *fakeLUKS {
	f.deviceSize[device] = bytes
	return f
}

// fails scripts an operation to return err.
func (f *fakeLUKS) fails(op string, err error) *fakeLUKS {
	f.fail[op] = err
	return f
}

// unlocked pre-opens a mapping over device, for a test that starts from a
// volume some earlier promotion already unlocked. The mapping is sized the
// way Open sizes one: from the device as it is scripted NOW.
func (f *fakeLUKS) unlocked(name, device string) *fakeLUKS {
	f.open[name] = device
	f.mappingSize[name] = f.deviceSize[device] - luks.HeaderBytes
	return f
}

func (f *fakeLUKS) record(op string, args ...string) error {
	f.r.record(luksBinary, append([]string{op}, args...)...)
	return f.fail[op]
}

func (f *fakeLUKS) Format(_ context.Context, device string, key *enclave.MemoryEnclave) error {
	if !f.holdsKey(key) {
		f.r.t.Errorf("Format was handed an empty passphrase for %s", device)
	}
	return f.record("format", device)
}

func (f *fakeLUKS) Open(_ context.Context, device, name string, key *enclave.MemoryEnclave) error {
	if !f.holdsKey(key) {
		f.r.t.Errorf("Open was handed an empty passphrase for %s", device)
	}
	if err := f.record("open", device, name); err != nil {
		return err
	}
	f.open[name] = device
	// Sized ONCE, here, from the device as it is now: go-luks2's Unlock does
	// the same, and nothing afterwards reloads it.
	f.mappingSize[name] = f.deviceSize[device] - luks.HeaderBytes
	return nil
}

func (f *fakeLUKS) Close(_ context.Context, name string) error {
	if err := f.record("close", name); err != nil {
		return err
	}
	delete(f.open, name)
	return nil
}

// holdsKey reports whether key is a live enclave with something in it.
func (f *fakeLUKS) holdsKey(key *enclave.MemoryEnclave) bool {
	if key == nil {
		return false
	}
	empty := true
	if err := key.WithBytes(func(b []byte) error {
		empty = len(b) == 0
		return nil
	}); err != nil {
		return false
	}
	return !empty
}

func (f *fakeLUKS) TestKey(_ context.Context, device string, _ *enclave.MemoryEnclave) error {
	return f.record("test-key", device)
}

func (f *fakeLUKS) DataOffset(_ context.Context, device string) (int64, error) {
	if err := f.record("data-offset", device); err != nil {
		return 0, err
	}
	return luks.HeaderBytes, nil
}

func (f *fakeLUKS) Mapping(_ context.Context, name string) (luks.MappingInfo, bool, error) {
	if err := f.record("mapping", name); err != nil {
		return luks.MappingInfo{}, false, err
	}
	backing, ok := f.open[name]
	if !ok {
		return luks.MappingInfo{}, false, nil
	}
	return luks.MappingInfo{
		Backing:          backing,
		BackingID:        fakeIdentity(backing),
		SizeBytes:        f.mappingSize[name],
		BackingSizeBytes: f.deviceSize[backing],
	}, true, nil
}

func (f *fakeLUKS) Identity(_ context.Context, path string) (string, error) {
	if err := f.record("identity", path); err != nil {
		return "", err
	}
	return fakeIdentity(path), nil
}

// fakeIdentity stands in for a device's major:minor. Distinct paths get
// distinct identities, which is all the ownership check needs to be able to
// tell "our device" from "somebody else's".
func fakeIdentity(path string) string { return "id(" + path + ")" }

// record appends a call to the same list the scripted commands land in,
// without consulting the response table: a LUKS operation is answered by
// fakeLUKS's own state rather than by a per-argv script.
func (f *fakeRunner) record(name string, args ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{Name: name, Args: append([]string(nil), args...)})
}

// newEncryptedProvider builds a provider configured for LUKS-above-DRBD over
// the scripted runner and a fake LUKS backend.
func newEncryptedProvider(t *testing.T) (*Provider, *fakeRunner, *fakeLUKS) {
	t.Helper()
	p, r, crypt, _ := newEncryptedProviderWithMounter(t)
	return p, r, crypt
}

// newEncryptedProviderWithMounter is the same, handing back the mount fake for
// the tests that assert on what Mount did and undid.
func newEncryptedProviderWithMounter(t *testing.T) (*Provider, *fakeRunner, *fakeLUKS, *mount.Fake) {
	t.Helper()

	keyFile := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(keyFile, []byte("a-test-passphrase-long-enough"), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}

	r := newFakeRunner(t)
	crypt := newFakeLUKS(r)
	m := &mount.Fake{}
	settings := testSettings(t)
	settings[SettingEncrypted] = "true"
	settings[SettingLUKSKeyFile] = keyFile

	p, err := New(settings,
		WithRunner(r),
		WithMounter(m),
		WithMountTable(r),
		WithBlockDevices(r),
		WithSecretProvider(testSecretProvider),
		withLUKSBackend(crypt),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, r, crypt, m
}

// cryptName is the device-mapper name the fixture provider gives a volume.
func cryptName(volID string) string {
	return luks.ReplicatedMappingPrefix + testVG + "." + volID
}

// cryptPath is where that mapping appears.
func cryptPath(volID string) string { return "/dev/mapper/" + cryptName(volID) }

// assertOrder requires the recorded calls to contain each of want, in this
// order. It is the assertion the crypt lifecycle is actually about: WHEN the
// container is opened and closed relative to the role change, not merely that
// it was.
func assertOrder(t *testing.T, r *fakeRunner, want ...string) {
	t.Helper()
	got := r.commands()
	at := -1
	for _, w := range want {
		found := -1
		for i := at + 1; i < len(got); i++ {
			if got[i] == w {
				found = i
				break
			}
		}
		if found == -1 {
			t.Fatalf("expected %q after position %d; calls were:\n  %v", w, at, got)
		}
		at = found
	}
}

// assertNotRun requires a call NOT to have happened. It is the half that proves
// a failure stopped the sequence rather than merely reporting it.
func assertNotRun(t *testing.T, r *fakeRunner, unwanted string) {
	t.Helper()
	for _, got := range r.commands() {
		if got == unwanted {
			t.Fatalf("%q ran and must not have; calls were:\n  %v", unwanted, r.commands())
		}
	}
}

// blkidEmpty scripts the device probe as a device carrying no signature at all,
// which is blkid's exit status 2.
func (f *fakeRunner) blkidEmpty(dev string) {
	f.on(binBlkid, "-p", "-o", "export", dev).fails(blkidNoSig, "")
}

// blkidReports scripts the device probe as finding a filesystem type.
func (f *fakeRunner) blkidReports(dev, fsType string) {
	f.on(binBlkid, "-p", "-o", "export", dev).returns(fmt.Sprintf("TYPE=%q\n", fsType))
}
