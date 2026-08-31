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

package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
)

// fakeCall records one command the provider issued.
type fakeCall struct {
	Name  string
	Args  []string
	Stdin []byte
}

// line renders a call the way a test asserts on it.
func (c fakeCall) line() string {
	if len(c.Args) == 0 {
		return c.Name
	}
	return c.Name + " " + strings.Join(c.Args, " ")
}

// responder answers one command.
type responder func(args []string, stdin []byte) ([]byte, error)

// fakeRunner is a CommandRunner that records every call and answers from a
// per-binary table, so a test states only the commands whose output it cares
// about and lets the rest succeed silently.
type fakeRunner struct {
	mu       sync.Mutex
	calls    []fakeCall
	handlers map[string]responder

	// What blkid reports for a device, shared with the LUKS fake so the two
	// cannot contradict each other: a device blkid calls a LUKS container is
	// one the LUKS backend will read a header off, which is how a real host
	// behaves and what stops a test from describing an impossible one.
	blkidTypes map[string]string

	// The device-mapper names the LUKS backend reports as open, each against
	// the device it is open over.
	luksBacking map[string]string

	// Data offsets for containers whose header is NOT the one this provider
	// formats — a volume restored from somebody else's snapshot. A container
	// absent from here reports luksHeaderBytes.
	luksOffsets map[string]int64

	// Devices whose container this provider's key does NOT open, which is what
	// the passphrase check is asked about.
	luksWrongKey map[string]bool

	// Devices whose header read fails, which is what a device node that has
	// gone away underneath a lockless read looks like.
	luksDumpFails map[string]bool

	// The same fake serves as the Mounter, so a test holds one object and can
	// assert on the exec'd commands and the mounts together. That half is the
	// shared recorder from internal/mount, embedded rather than reimplemented,
	// so pkg/drbd's tests drive the same one and the two cannot drift.
	*mount.Fake
}

// mountCalls returns the mounts recorded so far.
func (f *fakeRunner) mountCalls() []mount.Call { return f.MountCalls() }

// unmountCalls returns the unmount targets recorded so far.
func (f *fakeRunner) unmountCalls() []string { return f.UnmountCalls() }

// failMount makes the next mounts fail.
func (f *fakeRunner) failMount(err error) *fakeRunner {
	f.FailMount(err)
	return f
}

// failUnmount makes the next unmounts fail.
func (f *fakeRunner) failUnmount(err error) *fakeRunner {
	f.FailUnmount(err)
	return f
}

func newFakeRunner() *fakeRunner {
	f := &fakeRunner{
		handlers:      map[string]responder{},
		Fake:          &mount.Fake{},
		blkidTypes:    map[string]string{},
		luksBacking:   map[string]string{},
		luksOffsets:   map[string]int64{},
		luksWrongKey:  map[string]bool{},
		luksDumpFails: map[string]bool{},
	}
	f.handlers[luksBinary] = f.luks

	// An empty volume group, so a provider with no fixtures sees no volumes
	// rather than a parse failure.
	f.withLVs()

	// The 4 MiB extent LVM uses by default.
	f.withExtentSize(4 << 20)

	// A readable but empty mount table. The provider treats an unreadable one
	// as a failure now, so "nothing is mounted" has to be a real report.
	f.withMounts(nil)

	// No mapping is open. Defaulting the lookup to "found" would make every
	// plain volume look encrypted-and-open.
	f.withOpenMappings()

	// blkid answers "nothing here" with an exit status, never with a zero exit
	// and empty output — the provider treats the latter as malformed, so the
	// fake must not produce it.
	f.withBlkid(nil)

	return f
}

// fakeDeviceKey collapses the paths that lead to one device. /dev/<vg>/<lv> and
// /dev/mapper/<vg>-<lv> are symlinks to the same dm node, so both have to
// resolve alike or a device-identity check passes for the wrong reason.
func fakeDeviceKey(path string) string {
	if rest, ok := strings.CutPrefix(path, "/dev/mapper/"); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(path, "/dev/"); ok {
		if vg, lv, found := strings.Cut(rest, "/"); found {
			return dmName(vg, lv)
		}
		return rest
	}
	return path
}

var (
	fakeDeviceMu  sync.Mutex
	fakeDeviceIDs = map[string]string{}
)

// fakeDeviceIdentity hands each distinct device a stable major:minor.
func fakeDeviceIdentity(path string) string {
	key := fakeDeviceKey(path)

	fakeDeviceMu.Lock()
	defer fakeDeviceMu.Unlock()
	if id, ok := fakeDeviceIDs[key]; ok {
		return id
	}
	id := fmt.Sprintf("fc:%x", len(fakeDeviceIDs)+1)
	fakeDeviceIDs[key] = id
	return id
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	call := fakeCall{Name: name, Args: append([]string(nil), args...)}
	if stdin != nil {
		call.Stdin = append([]byte(nil), stdin...)
	}
	f.calls = append(f.calls, call)
	handler := f.handlers[name]
	f.mu.Unlock()

	if handler == nil {
		return nil, nil
	}
	return handler(args, stdin)
}

// on installs a responder for a binary.
func (f *fakeRunner) on(name string, r responder) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[name] = r
	return f
}

// fail makes a binary exit non-zero.
func (f *fakeRunner) fail(name string, code int, stderr string) *fakeRunner {
	return f.on(name, func(args []string, _ []byte) ([]byte, error) {
		return nil, &ExitError{Name: name, Args: args, Code: code, Stderr: stderr}
	})
}

// withLVs makes lvs report exactly these logical volumes.
func (f *fakeRunner) withLVs(lvs ...lvFixture) *fakeRunner {
	out := lvsJSON(lvs...)
	return f.on("lvs", func([]string, []byte) ([]byte, error) { return out, nil })
}

// withExtentSize makes vgs report the volume group's allocation unit.
func (f *fakeRunner) withExtentSize(bytes int64) *fakeRunner {
	out := fmt.Sprintf(`{"report":[{"vg":[{"vg_extent_size":"%d"}]}]}`, bytes)
	return f.on("vgs", func([]string, []byte) ([]byte, error) { return []byte(out), nil })
}

// withBlkid maps a device path to the TYPE blkid reports for it. A device
// absent from the map gets the exit status blkid uses for "no signature here".
func (f *fakeRunner) withBlkid(types map[string]string) *fakeRunner {
	f.mu.Lock()
	f.blkidTypes = map[string]string{}
	for device, fsType := range types {
		f.blkidTypes[device] = fsType
	}
	f.mu.Unlock()

	return f.on("blkid", func(args []string, _ []byte) ([]byte, error) {
		device := args[len(args)-1]
		f.mu.Lock()
		fsType, ok := f.blkidTypes[device]
		f.mu.Unlock()
		if !ok {
			return nil, &ExitError{Name: "blkid", Args: args, Code: blkidNoSignature}
		}
		return []byte("DEVNAME=" + device + "\nTYPE=" + fsType + "\n"), nil
	})
}

// withOpenMappings makes the LUKS backend report these device-mapper names as
// unlocked, each backed by the logical volume this provider would have opened
// it over, and every other name as absent.
func (f *fakeRunner) withOpenMappings(names ...string) *fakeRunner {
	backing := make(map[string]string, len(names))
	for _, n := range names {
		backing[n] = defaultBackingFor(n)
	}
	return f.withMappingsBackedBy(backing)
}

// withMappingsBackedBy is withOpenMappings with the backing device stated, for
// the case that matters: a mapping under this provider's deterministic name
// that belongs to something else.
func (f *fakeRunner) withMappingsBackedBy(backing map[string]string) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.luksBacking = map[string]string{}
	for name, device := range backing {
		f.luksBacking[name] = device
	}
	return f
}

// withLUKSHeader gives a device a data offset other than the one this provider
// formats with, which is what a container restored from an outside snapshot
// has.
func (f *fakeRunner) withLUKSHeader(device string, offset int64) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.luksOffsets[device] = offset
	return f
}

// withLUKSDumpFailure makes the header read fail for a device, which is how a
// device node that vanished under a lockless read behaves.
func (f *fakeRunner) withLUKSDumpFailure(device string) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.luksDumpFails[device] = true
	return f
}

// withLVsThen makes lvs report one set of logical volumes on its first call and
// another on every call after it, so a test can express the world changing
// underneath an operation that reads it twice.
func (f *fakeRunner) withLVsThen(first, rest []lvFixture) *fakeRunner {
	firstOut, restOut := lvsJSON(first...), lvsJSON(rest...)
	var calls int
	var mu sync.Mutex
	return f.on("lvs", func([]string, []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return firstOut, nil
		}
		return restOut, nil
	})
}

// withWrongKeyFor makes the passphrase check refuse these devices, modeling a
// KeyProvider whose key does not open that container.
func (f *fakeRunner) withWrongKeyFor(devices ...string) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, device := range devices {
		f.luksWrongKey[device] = true
	}
	return f
}

// luksBinary is the name the fake records LUKS operations under.
//
// They are not a binary any more — go-luks2 does the work in this process — but
// they go through the same recorder as the commands that still are, and for the
// reason a second recorder would have destroyed: the assertions that matter are
// about ORDER across the two. The tag is written after the format; the mapping
// is closed before the lvremove; the container resize happens before resize2fs.
// A test cannot check any of that against two lists.
const luksBinary = "luks"

// The fake is the provider's luksBackend as well as its CommandRunner and its
// Mounter, so one object describes the whole host a test is pretending to be.
var _ luksBackend = (*fakeRunner)(nil)

func (f *fakeRunner) Format(ctx context.Context, device string, key []byte) error {
	_, err := f.Run(ctx, key, luksBinary, "format", device)
	return err
}

func (f *fakeRunner) Open(ctx context.Context, device, name string, key []byte) error {
	_, err := f.Run(ctx, key, luksBinary, "open", device, name)
	return err
}

func (f *fakeRunner) Close(ctx context.Context, name string) error {
	_, err := f.Run(ctx, nil, luksBinary, "close", name)
	return err
}

func (f *fakeRunner) TestKey(ctx context.Context, device string, key []byte) error {
	_, err := f.Run(ctx, key, luksBinary, "test-key", device)
	return err
}

func (f *fakeRunner) DataOffset(ctx context.Context, device string) (int64, error) {
	out, err := f.Run(ctx, nil, luksBinary, "data-offset", device)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
}

func (f *fakeRunner) Mapping(ctx context.Context, name string) (mappingInfo, bool, error) {
	out, err := f.Run(ctx, nil, luksBinary, "mapping", name)
	if err != nil {
		return mappingInfo{}, false, err
	}
	backing := strings.TrimSpace(string(out))
	if backing == "" {
		return mappingInfo{}, false, nil
	}
	return mappingInfo{Backing: backing, BackingID: fakeDeviceIdentity(backing)}, true, nil
}

func (f *fakeRunner) Identity(ctx context.Context, path string) (string, error) {
	out, err := f.Run(ctx, nil, luksBinary, "identity", path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// luks answers the LUKS operations the provider issues, from the fake's own
// state rather than from a per-test closure.
//
// One handler for all of them, because the provider issues several against one
// volume and a test usually cares about more than one: a Status over an
// encrypted volume asks whether the mapping is open AND reads its header, so a
// fake where installing an answer for either replaced the other could not
// describe that volume at all.
//
// Whether a device HAS a header is not tracked separately — it is whatever
// blkid was told to report for the device. A container the LUKS backend reads a
// header off but blkid calls ext4 is not a host any test should be able to
// describe.
func (f *fakeRunner) luks(args []string, _ []byte) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	// The trailing argument: a mapping NAME for close, a device PATH for the
	// header operations, and for open the name follows the device.
	target := args[len(args)-1]

	switch args[0] {
	case "mapping":
		f.mu.Lock()
		backing := f.luksBacking[target]
		f.mu.Unlock()
		// The empty answer is "no mapping under that name", which is what the
		// provider reads as not unlocked.
		return []byte(backing), nil

	case "open":
		// A successful unlock leaves a mapping behind, and a successful close
		// takes one away. The fake tracks that rather than answering from a
		// fixed table, because the questions worth asking of it are about what
		// SURVIVES an operation — a rollback that must not close somebody
		// else's mapping, a failed resize that must not lose the caller's. A
		// fake whose mapping set never moved answered every one of those with
		// whatever the test set up, which is to say it answered none of them.
		//
		// args is ["open", device, name]: the device is what the mapping ends
		// up over, and the name is what it answers to.
		if len(args) >= 3 {
			f.mu.Lock()
			f.luksBacking[args[2]] = defaultBackingFor(args[2])
			f.mu.Unlock()
		}
		return nil, nil

	case "close":
		f.mu.Lock()
		delete(f.luksBacking, target)
		f.mu.Unlock()
		return nil, nil

	case "identity":
		return []byte(fakeDeviceIdentity(target)), nil

	case "data-offset":
		f.mu.Lock()
		gone := f.luksDumpFails[target]
		f.mu.Unlock()
		if gone {
			return nil, fmt.Errorf("device %s does not exist or access denied", target)
		}
		offset, ok := f.luksHeaderOf(target)
		if !ok {
			return nil, fmt.Errorf("device %s is not a valid LUKS device", target)
		}
		return []byte(strconv.FormatInt(offset, 10)), nil

	case "test-key":
		if _, ok := f.luksHeaderOf(target); !ok {
			return nil, fmt.Errorf("device %s is not a valid LUKS device", target)
		}
		f.mu.Lock()
		wrong := f.luksWrongKey[target]
		f.mu.Unlock()
		if wrong {
			return nil, errors.New("no key available with this passphrase")
		}
		return nil, nil
	}
	return nil, nil
}

// luksHeaderOf reports the data offset of the container on a device, and
// whether it has one at all — which it does exactly when blkid calls it a LUKS
// container. Absent an explicit override the offset is the one this provider
// formats with.
func (f *fakeRunner) luksHeaderOf(device string) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blkidTypes[device] != fsTypeLUKS {
		return 0, false
	}
	if offset, ok := f.luksOffsets[device]; ok {
		return offset, true
	}
	return luksHeaderBytes, true
}

// defaultBackingFor turns a mapping name back into the logical volume this
// provider opens it over: "bs-<vg>_<vol>" is backed by /dev/mapper/<vg>-<vol>,
// which is the dm-canonical spelling sysfs leads to.
func defaultBackingFor(mapping string) string {
	rest := strings.TrimPrefix(mapping, mappingPrefix)
	vg, vol, found := strings.Cut(rest, "_")
	if !found {
		return "/dev/mapper/" + rest
	}
	return "/dev/mapper/" + dmName(vg, vol)
}

// withMounts maps a device path to the targets it is mounted at, and renders
// the whole thing as the flat mount table `findmnt --list --json` produces.
//
// The fake answers with the WHOLE table however it is asked, because that is
// what the provider now does: it enumerates and filters locally rather than
// letting findmnt filter, so that a findmnt which cannot read the mount table is
// distinguishable from a volume that is not mounted.
func (f *fakeRunner) withMounts(mounts map[string][]string) *fakeRunner {
	rows := make([]mountRow, 0, len(mounts))
	for device, targets := range mounts {
		for _, target := range targets {
			rows = append(rows, mountRow{Target: target, Source: device})
		}
	}
	// A real mount table holds unrelated entries; keeping one here means a test
	// passes only if the provider actually filters.
	rows = append(rows, mountRow{Target: "/", Source: "/dev/sda1"})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Target < rows[j].Target })

	out := findmntJSON(rows...)
	return f.on("findmnt", func([]string, []byte) ([]byte, error) { return out, nil })
}

// mountRow is one entry of the mount table the fake reports.
type mountRow struct {
	Target string `json:"target"`
	Source string `json:"source"`
}

// findmntJSON renders rows as `findmnt --list --json` output.
func findmntJSON(rows ...mountRow) []byte {
	report := struct {
		Filesystems []mountRow `json:"filesystems"`
	}{Filesystems: rows}
	out, err := json.Marshal(report)
	if err != nil {
		panic("findmntJSON: " + err.Error())
	}
	return out
}

// snapshot returns a copy of the calls recorded so far.
func (f *fakeRunner) snapshot() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// lines renders every recorded call.
func (f *fakeRunner) lines() []string {
	calls := f.snapshot()
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.line())
	}
	return out
}

// find returns the first recorded call to a binary, and whether there was one.
func (f *fakeRunner) find(name string) (fakeCall, bool) {
	for _, c := range f.snapshot() {
		if c.Name == name {
			return c, true
		}
	}
	return fakeCall{}, false
}

// mustFind fails the test when a binary was never invoked.
func (f *fakeRunner) mustFind(t *testing.T, name string) fakeCall {
	t.Helper()
	call, ok := f.find(name)
	if !ok {
		t.Fatalf("expected a %s call; got %v", name, f.lines())
	}
	return call
}

// mustNotRun fails the test when a binary was invoked.
func (f *fakeRunner) mustNotRun(t *testing.T, name string) {
	t.Helper()
	if call, ok := f.find(name); ok {
		t.Fatalf("expected no %s call; got %q", name, call.line())
	}
}

// lvFixture describes one logical volume for lvs to report.
type lvFixture struct {
	Name        string
	SizeBytes   int64
	Active      bool
	Origin      string
	Time        string
	DataPercent string

	// OriginSizeBytes overrides the image size a SNAPSHOT reports. Left zero it
	// follows the origin's current size, which is the ordinary case; setting it
	// expresses an origin that has been grown since the snapshot was taken.
	OriginSizeBytes int64

	// Tags are the LVM tags on the volume. A fixture with none models a volume
	// provisioned before this provider tagged them.
	Tags []string
}

// attr renders an lv_attr string whose state field matches Active. Only the
// fifth character is read by the provider; the rest is plausible filler.
func (f lvFixture) attr() string {
	state := "-"
	if f.Active {
		state = "a"
	}
	return "-wi-" + state + "-----"
}

// lvsJSON renders the fixtures as `lvs --reportformat json` output.
func lvsJSON(lvs ...lvFixture) []byte {
	type lvJSON struct {
		Name        string `json:"lv_name"`
		Size        string `json:"lv_size"`
		Attr        string `json:"lv_attr"`
		Origin      string `json:"origin"`
		Time        string `json:"lv_time"`
		DataPercent string `json:"data_percent"`
		OriginSize  string `json:"origin_size"`
		Tags        string `json:"lv_tags"`
	}
	type reportJSON struct {
		Report []struct {
			LV []lvJSON `json:"lv"`
		} `json:"report"`
	}

	var report reportJSON
	report.Report = append(report.Report, struct {
		LV []lvJSON `json:"lv"`
	}{})
	for _, lv := range lvs {
		// lvs populates data_percent only where the kernel is tracking it: an
		// ACTIVE snapshot. A plain volume reports empty, and so does an
		// inactive snapshot. Emitting anything else here would let a test pass
		// against output real LVM never produces — which is exactly how the
		// "every snapshot reports occupancy" rule got written and then failed
		// against a real volume group.
		dataPercent := ""
		if lv.Origin != "" && lv.Active {
			dataPercent = lv.DataPercent
			if dataPercent == "" {
				dataPercent = "0.00"
			}
		}
		// origin_size, as measured: a snapshot reports the size its origin had
		// when it was taken; an origin that HAS a snapshot reports its own
		// current size; an ordinary volume reports nothing. Emitting anything
		// else lets a test agree with a rule real LVM would refuse.
		originSize := ""
		switch {
		case lv.Origin != "":
			size := lv.OriginSizeBytes
			if size == 0 {
				size = originSizeOf(lvs, lv.Origin)
			}
			originSize = fmt.Sprintf("%d", size)
		case hasSnapshotIn(lvs, lv.Name):
			originSize = fmt.Sprintf("%d", lv.SizeBytes)
		}

		// lv_tags is a comma-separated list, and the EMPTY STRING for a volume
		// with no tags — measured, including through the JSON report, where it
		// is "" rather than absent or null. A fake that omitted the field would
		// let a parser that mishandles the empty case pass.
		//
		// Tags are also not inherited by snapshots, measured, so a fixture is
		// tagged only where it says so.
		report.Report[0].LV = append(report.Report[0].LV, lvJSON{
			Name:        lv.Name,
			Size:        fmt.Sprintf("%d", lv.SizeBytes),
			Attr:        lv.attr(),
			Origin:      lv.Origin,
			Time:        lv.Time,
			DataPercent: dataPercent,
			OriginSize:  originSize,
			Tags:        strings.Join(lv.Tags, ","),
		})
	}

	out, err := json.Marshal(report)
	if err != nil {
		panic("lvsJSON: " + err.Error())
	}
	return out
}

// originSizeOf reports the current size of a named origin among the fixtures.
func originSizeOf(lvs []lvFixture, name string) int64 {
	for _, lv := range lvs {
		if lv.Name == name {
			return lv.SizeBytes
		}
	}
	return 0
}

// hasSnapshotIn reports whether any fixture is a snapshot of this volume.
func hasSnapshotIn(lvs []lvFixture, name string) bool {
	for _, lv := range lvs {
		if lv.Origin == name {
			return true
		}
	}
	return false
}

// newTestProvider builds a provider over the fake with a fixed node ID, so
// assertions on node identity do not depend on the test host's hostname.
func newTestProvider(t *testing.T, runner *fakeRunner, mutate ...func(*Options)) *Provider {
	t.Helper()
	opts := Options{
		VolumeGroup: "vg0",
		NodeID:      "node-a",
		Runner:      runner,
		Mounter:     runner,
		luks:        runner,
		// Per-test, so tests cannot serialize against each other through a
		// shared directory — and so a test host without /run/lock still runs.
		LockDir: t.TempDir(),
	}
	for _, m := range mutate {
		m(&opts)
	}
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}
