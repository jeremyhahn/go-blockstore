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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
)

// fakeRunner is a CommandRunner scripted by exact argv.
//
// Matching on the whole argv rather than on the binary name is deliberate: a
// test that scripts "drbdadm primary vol1" fails if the provider runs "drbdadm
// primary --force vol1", which is the property the force-refusal test needs and
// which a looser matcher would not give.
//
// An unscripted command fails the test rather than returning a zero value, so a
// method that starts calling something new cannot pass on the old script.
type fakeRunner struct {
	t *testing.T

	mu        sync.Mutex
	responses map[string]*fakeResponse
	calls     []fakeCall

	// The kernel mount table this provider sees: device path to the paths it
	// is mounted at, and the error to report instead of an answer.
	mounted       map[string][]string
	deviceAliases map[string]string
	overMounted   map[string]string
	mountTableErr error
	tableLookups  int
	tableHook     func()

	// The block-device work, recorded rather than performed, and the failures
	// and hooks a test scripts onto it.
	copies   []copyCall
	zeroes   []zeroCall
	copyErr  error
	zeroErr  error
	copyHook func()
	zeroHook func()
}

// copyCall and zeroCall are the block-device operations the provider asked for.
type copyCall struct {
	Source      string
	Destination string
}

type zeroCall struct {
	Device string
	Offset int64
}

type fakeCall struct {
	Name string
	Args []string
}

func (c fakeCall) String() string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

type fakeResponse struct {
	stdout     string
	exitCode   int
	stderr     string
	shouldFail bool
	count      int
	hook       func()
}

// testMountPoint is a real directory that exists for the lifetime of the test
// binary.
//
// Mount checks its target with Lstat immediately before mounting — a symlink
// there would be followed by mount(8)'s canonicalization — so the scripted
// tests need a target that is genuinely a directory rather than a plausible
// string. Created once because it is read-only as far as the tests care.
var testMountPoint string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gobs-drbd-mnt")
	if err != nil {
		panic("creating the test mount point: " + err.Error())
	}
	testMountPoint = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newFakeRunner(t *testing.T) *fakeRunner {
	t.Helper()
	return &fakeRunner{t: t, responses: make(map[string]*fakeResponse)}
}

func runnerKey(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), "\x00")
}

// on scripts a command. Calling it twice for the same argv replaces the
// previous script, which is how a test moves a resource from one DRBD state to
// the next between phases.
func (f *fakeRunner) on(name string, args ...string) *fakeResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &fakeResponse{}
	f.responses[runnerKey(name, args...)] = r
	return r
}

// returns scripts a successful command with the given standard output.
func (r *fakeResponse) returns(stdout string) *fakeResponse {
	r.stdout, r.shouldFail = stdout, false
	return r
}

// fails scripts a command that exits non-zero.
func (r *fakeResponse) fails(code int, stderr string) *fakeResponse {
	r.shouldFail, r.exitCode, r.stderr = true, code, stderr
	return r
}

// then registers a function to run after the command has been answered. It is
// how a test simulates the caller's context being canceled midway through an
// operation.
func (r *fakeResponse) then(hook func()) *fakeResponse {
	r.hook = hook
	return r
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.mu.Lock()
	call := fakeCall{Name: name, Args: append([]string(nil), args...)}
	f.calls = append(f.calls, call)
	r, ok := f.responses[runnerKey(name, args...)]
	if ok {
		r.count++
	}
	f.mu.Unlock()

	if ok && r.hook != nil {
		r.hook()
	}

	if !ok {
		f.t.Errorf("unscripted command: %s", call)
		return nil, &CommandError{Cmd: name, Args: args, ExitCode: 127, Stderr: "unscripted"}
	}
	if r.shouldFail {
		return nil, &CommandError{Cmd: name, Args: args, ExitCode: r.exitCode, Stderr: r.stderr}
	}
	return []byte(r.stdout), nil
}

// The mount-table seam. It answers as /proc/self/mountinfo would, which the
// provider reads instead of asking findmnt: a device that is not mounted is an
// empty answer and NOT an error, and a table that could not be read is an
// error and NEVER an empty answer. Keeping those apart is the whole reason the
// lookup moved off findmnt, whose single non-zero exit meant both.

// scriptMountUnderAlias mounts a device at target under one of its OTHER names,
// the way a filesystem mounted through /dev/drbd/by-res/<res>/0 appears in the
// table. The mount belongs to canonical all the same.
func (f *fakeRunner) scriptMountUnderAlias(alias, canonical, target string) {
	f.scriptMount(alias, target)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deviceAliases == nil {
		f.deviceAliases = make(map[string]string)
	}
	f.deviceAliases[alias] = canonical
}

// failMountTable makes the mount table unreadable.
func (f *fakeRunner) failMountTable(err error) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mountTableErr = err
	return f
}

// onMountTable registers a function to run while a mount lookup is in flight.
// It is how a test holds a caller inside the window between reading the table
// and acting on what it said.
func (f *fakeRunner) onMountTable(hook func()) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tableHook = hook
	return f
}

// MountPointsFor returns where the device is mounted.
func (f *fakeRunner) MountPointsFor(_ context.Context, device string) ([]string, error) {
	f.mu.Lock()
	f.tableLookups++
	hook, tableErr := f.tableHook, f.mountTableErr
	targets := append([]string(nil), f.mounted[device]...)
	// A device is one device however it is spelled, which is what matching by
	// major:minor gives the real implementation and what this reproduces: a
	// mount made under an alias belongs to the device the alias names.
	for alias, canonical := range f.deviceAliases {
		if canonical == device {
			targets = append(targets, f.mounted[alias]...)
		}
	}
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	if tableErr != nil {
		return nil, tableErr
	}
	return targets, nil
}

// VisibleMountPointsFor answers with the mounts that have not been covered by
// something mounted on top of them, which is what umount(2) would detach.
func (f *fakeRunner) VisibleMountPointsFor(ctx context.Context, device string) ([]string, error) {
	targets, err := f.MountPointsFor(ctx, device)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	var visible []string
	for _, target := range targets {
		if top, covered := f.overMounted[target]; covered && top != device {
			continue
		}
		visible = append(visible, target)
	}
	return visible, nil
}

// PropagationOf answers about this device at the path. This provider does not
// use it yet — the seam carries it because the mount table does — so the fake
// answers the way an ordinary host mount does rather than pretending the
// question cannot be asked.
func (f *fakeRunner) PropagationOf(_ context.Context, device, mountPoint string) (uint32, bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mountTableErr != nil {
		return 0, false, "", f.mountTableErr
	}
	for _, target := range f.mounted[device] {
		if target == mountPoint {
			return 1, false, "private", nil
		}
	}
	return 0, false, "", &mountinfo.MountPointError{MountPoint: mountPoint, Err: mountinfo.ErrNotMounted}
}

// overMount covers a path with another device's filesystem. What was mounted
// there stays mounted and stops being what is visible.
func (f *fakeRunner) overMount(target, device string) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overMounted == nil {
		f.overMounted = make(map[string]string)
	}
	f.overMounted[target] = device
	return f
}

// mountLookups is how many times the mount table was consulted. A method that
// looks nothing up is a decision worth pinning: it is what keeps a raw volume
// from reading the table for a filesystem it does not have.
func (f *fakeRunner) mountLookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tableLookups
}

// The block-device seam, standing in for what dd and blkdiscard used to do.
// The calls are recorded into the same log as the commands, so a test that
// orders a copy or a wipe against the LVM and DRBD calls around it still can.

// failCopy makes the block-device copy fail.
func (f *fakeRunner) failCopy(err error) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copyErr = err
	return f
}

// failZeroOut makes the zeroing fail.
func (f *fakeRunner) failZeroOut(err error) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zeroErr = err
	return f
}

// onZeroOut registers a function to run while the zeroing is in flight. It is
// how a test cancels a context during the step that takes minutes per terabyte
// on real hardware.
func (f *fakeRunner) onZeroOut(hook func()) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zeroHook = hook
	return f
}

// Copy records the copy the provider asked for.
func (f *fakeRunner) Copy(ctx context.Context, src, dst string) error {
	f.mu.Lock()
	f.copies = append(f.copies, copyCall{Source: src, Destination: dst})
	f.calls = append(f.calls, fakeCall{Name: "copy", Args: []string{src, dst}})
	hook, err := f.copyHook, f.copyErr
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

// ZeroOut records the zeroing the provider asked for.
func (f *fakeRunner) ZeroOut(ctx context.Context, device string, offset int64) error {
	f.mu.Lock()
	f.zeroes = append(f.zeroes, zeroCall{Device: device, Offset: offset})
	f.calls = append(f.calls, fakeCall{Name: "zeroout", Args: []string{device, strconv.FormatInt(offset, 10)}})
	hook, err := f.zeroHook, f.zeroErr
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

// zeroCalls returns the zeroing the provider asked for.
func (f *fakeRunner) zeroCalls() []zeroCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]zeroCall(nil), f.zeroes...)
}

// copyCalls returns the copies the provider asked for.
func (f *fakeRunner) copyCalls() []copyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]copyCall(nil), f.copies...)
}

// commands returns every call made so far, one "binary arg arg" line each.
func (f *fakeRunner) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.String())
	}
	return out
}

// assertRan fails unless the exact command line was run.
func (f *fakeRunner) assertRan(t *testing.T, want string) {
	t.Helper()
	for _, got := range f.commands() {
		if got == want {
			return
		}
	}
	t.Errorf("command %q was not run; ran:\n  %s", want, strings.Join(f.commands(), "\n  "))
}

// assertNotRan fails if any command line contains the given substring. It is
// how the force-refusal tests prove a flag never reached drbdadm.
func (f *fakeRunner) assertNotRan(t *testing.T, substr string) {
	t.Helper()
	for _, got := range f.commands() {
		if strings.Contains(got, substr) {
			t.Errorf("command containing %q was run: %q", substr, got)
		}
	}
}

// reset clears the recorded calls, leaving the script in place.
func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
	f.copies, f.zeroes, f.tableLookups = nil, nil, 0
}

// -----------------------------------------------------------------------------
// Provider fixtures
// -----------------------------------------------------------------------------

const (
	testVG     = "vg0"
	testNode   = "node-a"
	testPeer   = "node-b"
	testVolume = "vol1"

	// testSecret is a shared secret in the shape validateSharedSecret accepts:
	// printable ASCII, no quote, no backslash, within DRBD's 64-byte limit.
	testSecret = "s3cr3t-replication-key-for-tests"

	// testExtentSize is LVM's default allocation unit, which every logical
	// volume's size is rounded up to.
	testExtentSize = int64(4) << 20
)

// testSettings is the settings map the provider fixtures are built from, with
// the two directories pointed at a temporary tree.
func testSettings(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		SettingVolumeGroup: testVG,
		SettingConfigDir:   filepath.Join(dir, "drbd.d"),
		SettingStateDir:    filepath.Join(dir, "state"),
		SettingNodeName:    testNode,
		SettingNodeAddress: "10.10.0.1",
		SettingPeerNode:    testPeer,
		SettingPeerAddress: "10.10.0.2",
	}
}

// newTestProvider builds a provider over a scripted runner and the shared fake
// mounter.
//
// Mounting does not go through the runner: a target has to be PINNED to a
// descriptor before it is mounted on, which no exec'd binary can be made to do,
// so it goes through internal/mount's seam instead. The fake there is the one
// pkg/local's tests drive too — one recorder for one interface, so neither
// provider's tests can pass against a fake the other has outgrown.
func newTestProvider(t *testing.T) (*Provider, *fakeRunner) {
	t.Helper()
	p, r, _ := newTestProviderWithMounter(t)
	return p, r
}

func newTestProviderWithMounter(t *testing.T) (*Provider, *fakeRunner, *mount.Fake) {
	t.Helper()
	return newTestProviderWith(t, nil)
}

// newTestProviderWith is the same over settings the caller adjusts first, for
// the tests that need a non-default option.
func newTestProviderWith(t *testing.T, tweak func(map[string]string)) (*Provider, *fakeRunner, *mount.Fake) {
	t.Helper()
	r := newFakeRunner(t)
	m := &mount.Fake{}
	settings := testSettings(t)
	if tweak != nil {
		tweak(settings)
	}
	p, err := New(settings,
		WithRunner(r),
		WithMounter(m),
		WithMountTable(r),
		WithBlockDevices(r),
		WithSecretProvider(testSecretProvider),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, r, m
}

// testSecretProvider hands out testSecret, in the enclave the contract calls
// for. Every fixture provider gets one, because New refuses to build a provider
// with no way to authenticate its peer.
func testSecretProvider(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
	enc, err := enclave.NewMemoryEnclaveSized(len(testSecret))
	if err != nil {
		return nil, err
	}
	if err := enc.WithBytes(func(buf []byte) error {
		copy(buf, testSecret)
		return nil
	}); err != nil {
		enc.Destroy()
		return nil, err
	}
	return enc, nil
}

// fixture reads a testdata file.
func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %q: %v", name, err)
	}
	return string(data)
}

// lvsJSON renders an lvs report of the given entries, in the shape LVM emits
// with --reportformat json: every field a string, numbers included.
func lvsJSON(entries ...lvEntry) string {
	var b strings.Builder
	b.WriteString(`{"report":[{"lv":[`)
	for i := range entries {
		e := &entries[i]
		if i > 0 {
			b.WriteByte(',')
		}
		extent := e.ExtentSize
		if extent == "" {
			extent = strconv.FormatInt(testExtentSize, 10)
		}
		b.WriteString(`{"lv_name":"` + e.Name + `","vg_name":"` + e.VG +
			`","lv_size":"` + e.Size + `","origin":"` + e.Origin +
			`","origin_size":"` + e.OriginSize + `","lv_time":"` + e.Time +
			`","lv_attr":"` + e.Attr + `","vg_extent_size":"` + extent +
			`","data_percent":"` + e.DataPercent + `"}`)
	}
	b.WriteString(`]}]}`)
	return b.String()
}

// emptyStatus is what drbdsetup reports on a node with no resources up.
const emptyStatus = `[]`

// scriptLVS scripts the one lvs invocation this package makes.
func (f *fakeRunner) scriptLVS(out string) {
	f.on(binLVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", lvsFields, testVG).returns(out)
}

// scriptMount puts the device in the mount table at target. An empty target
// leaves it unmounted, which the table reports as an empty answer rather than
// as a failure.
func (f *fakeRunner) scriptMount(dev, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mounted == nil {
		f.mounted = make(map[string][]string)
	}
	if target == "" {
		delete(f.mounted, dev)
		return
	}
	f.mounted[dev] = []string{target}
}

// scriptStatus scripts the one drbdsetup invocation this package makes.
func (f *fakeRunner) scriptStatus(out string) {
	f.on(binDRBDSetup, "status", "--json").returns(out)
}

// The mount assertions. Mounting does not go through the command runner, so
// these read the shared fake's record instead of the command log — and they
// assert on flags and data separately, which is what mount(2) is actually
// given, rather than on an -o string nobody constructs any more.

func assertMounted(t *testing.T, m *mount.Fake, source, target, fsType string, flags uintptr, data string) {
	t.Helper()
	calls := m.MountCalls()
	for _, c := range calls {
		if c.Source != source || c.Target != target {
			continue
		}
		if c.FSType != fsType {
			t.Errorf("mounted %q as %q, want %q", target, c.FSType, fsType)
		}
		if c.Flags != flags {
			t.Errorf("mounted %q with flags %#x, want %#x", target, c.Flags, flags)
		}
		if c.Data != data {
			t.Errorf("mounted %q with data %q, want %q", target, c.Data, data)
		}
		return
	}
	t.Errorf("%q was not mounted from %q; mounts: %+v", target, source, calls)
}

func assertUnmounted(t *testing.T, m *mount.Fake, target string) {
	t.Helper()
	for _, got := range m.UnmountCalls() {
		if got == target {
			return
		}
	}
	t.Errorf("%q was not unmounted; unmounts: %v", target, m.UnmountCalls())
}

func assertNoMount(t *testing.T, m *mount.Fake) {
	t.Helper()
	if calls := m.MountCalls(); len(calls) != 0 {
		t.Errorf("something was mounted: %+v", calls)
	}
}

func assertNoUnmount(t *testing.T, m *mount.Fake) {
	t.Helper()
	if calls := m.UnmountCalls(); len(calls) != 0 {
		t.Errorf("something was unmounted: %v", calls)
	}
}

// The block-device assertions, reading the recorded operations rather than a
// command line. An exit status from dd said nothing about what was copied; the
// recorded call says both ends.

func assertCopied(t *testing.T, r *fakeRunner, src, dst string) {
	t.Helper()
	for _, c := range r.copyCalls() {
		if c.Source == src && c.Destination == dst {
			return
		}
	}
	t.Errorf("%s was not copied to %s; copies: %+v", src, dst, r.copyCalls())
}

func assertZeroed(t *testing.T, r *fakeRunner, device string, offset int64) {
	t.Helper()
	for _, z := range r.zeroCalls() {
		if z.Device == device && z.Offset == offset {
			return
		}
	}
	t.Errorf("%s was not zeroed from %d; zeroing: %+v", device, offset, r.zeroCalls())
}

func assertNothingZeroed(t *testing.T, r *fakeRunner) {
	t.Helper()
	if z := r.zeroCalls(); len(z) != 0 {
		t.Errorf("something was zeroed: %+v", z)
	}
}
