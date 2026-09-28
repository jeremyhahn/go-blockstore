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

package preflightmatrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

func TestProbeCapabilities(t *testing.T) {
	cases := map[string][]preflight.Capability{
		ModeMount:       {preflight.CapabilityMount},
		ModeNetAdmin:    {preflight.CapabilityNetAdmin},
		ModeDRBDControl: {preflight.CapabilityDRBDControl},
		ModeDMKeyring:   {preflight.CapabilityDeviceMapper, preflight.CapabilityKernelKeyring},
		"":              {preflight.CapabilityDeviceMapper, preflight.CapabilityKernelKeyring},
	}
	for mode, want := range cases {
		if got := ProbeCapabilities(mode); !slices.Equal(got, want) {
			t.Errorf("ProbeCapabilities(%q) = %v, want %v", mode, got, want)
		}
	}
}

func TestProbe(t *testing.T) {
	var asked []preflight.Capability
	pass := func(_ context.Context, caps ...preflight.Capability) error { asked = caps; return nil }
	var out bytes.Buffer
	if code := Probe(context.Background(), ModeNetAdmin, pass, &out); code != 0 || out.String() != "PASS\n" {
		t.Fatalf("Probe pass = %d, %q", code, out.String())
	}
	if !slices.Equal(asked, []preflight.Capability{preflight.CapabilityNetAdmin}) {
		t.Errorf("Probe asked for %v", asked)
	}

	refuse := func(context.Context, ...preflight.Capability) error {
		return errors.New("kernel-keyring is unavailable")
	}
	out.Reset()
	if code := Probe(context.Background(), ModeDMKeyring, refuse, &out); code != 1 ||
		out.String() != "REFUSED\nkernel-keyring is unavailable\n" {
		t.Fatalf("Probe refuse = %d, %q", code, out.String())
	}
}

func TestProfile(t *testing.T) {
	decode := func(t *testing.T, keyring bool, drop ...string) []string {
		t.Helper()
		content, err := Profile(keyring, drop...)
		if err != nil {
			t.Fatal(err)
		}
		var p seccompProfile
		if err := json.Unmarshal(content, &p); err != nil {
			t.Fatalf("the profile is not JSON: %v", err)
		}
		if p.DefaultAction != "SCMP_ACT_ERRNO" || len(p.Syscalls) != 1 || p.Syscalls[0].Action != "SCMP_ACT_ALLOW" {
			t.Fatalf("the profile is not default-deny with one allow list: %+v", p)
		}
		return p.Syscalls[0].Names
	}
	narrow := decode(t, true)
	for _, name := range append(slices.Clone(keyringSyscalls), "mount", "ioctl", "socket") {
		if !slices.Contains(narrow, name) {
			t.Errorf("the narrow profile does not allow %s", name)
		}
	}
	without := decode(t, false, "mount")
	for _, name := range append(slices.Clone(keyringSyscalls), "mount") {
		if slices.Contains(without, name) {
			t.Errorf("the reduced profile still allows %s", name)
		}
	}
}

func TestWriteProfiles(t *testing.T) {
	dir := t.TempDir()
	profiles, err := WriteProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{profiles.Narrow, profiles.WithoutKeyring, profiles.WithoutMount, profiles.WithoutIoctl} {
		if filepath.Dir(path) != dir {
			t.Errorf("%s is not in %s", path, dir)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("profile not written: %v", err)
		}
	}
	var profileErr *ProfileError
	if _, err := WriteProfiles(filepath.Join(dir, "absent")); !errors.As(err, &profileErr) || profileErr.Unwrap() == nil {
		t.Fatalf("WriteProfiles into a missing directory = %v, want a ProfileError", err)
	}
	if !strings.Contains(profileErr.Error(), "narrow.json") {
		t.Errorf("ProfileError = %q", profileErr)
	}
}

func testProfiles() Profiles {
	return Profiles{Narrow: "/p/narrow.json", WithoutKeyring: "/p/nk.json", WithoutMount: "/p/nm.json", WithoutIoctl: "/p/ni.json"}
}

// TestCases keeps the matrix's shape: fourteen rows, two passes (without which
// the guard could be one that refuses everything), a needle on every refusal,
// every generated profile used, and --privileged nowhere.
func TestCases(t *testing.T) {
	cases := Cases(testProfiles())
	if len(cases) != 14 {
		t.Fatalf("%d rows, want 14", len(cases))
	}
	passes := 0
	used := map[string]bool{}
	for _, c := range cases {
		if c.Expect == Pass {
			passes++
		} else if c.Needle == "" {
			t.Errorf("%q refuses without saying what the refusal must name", c.Name)
		}
		for _, arg := range c.Args {
			if strings.Contains(arg, "privileged") {
				t.Errorf("%q passes %s, which proves nothing", c.Name, arg)
			}
			if strings.HasPrefix(arg, "seccomp=") {
				used[strings.TrimPrefix(arg, "seccomp=")] = true
			}
		}
	}
	if passes != 2 {
		t.Errorf("%d passing rows, want 2", passes)
	}
	p := testProfiles()
	for _, path := range []string{p.Narrow, p.WithoutKeyring, p.WithoutMount, p.WithoutIoctl} {
		if !used[path] {
			t.Errorf("no row uses %s", path)
		}
	}
}

// behaves is a container runtime in which the guard does exactly what each row
// claims.
func behaves(ctx context.Context, args []string) (string, bool, error) {
	for _, c := range Cases(testProfiles()) {
		want := append([]string{"run", "--rm", "-v", "/probe:/preflight-probe:ro", "--user", "0"}, c.Args...)
		want = append(want, "img", "/preflight-probe", c.Mode)
		if slices.Equal(args, want) {
			if c.Expect == Pass {
				return "PASS\n", true, nil
			}
			return "REFUSED\nsomething " + c.Needle + " something\n", false, nil
		}
	}
	return "", false, errors.New("unexpected invocation")
}

func TestRun(t *testing.T) {
	cases := Cases(testProfiles())
	var out bytes.Buffer
	failures, err := Run(context.Background(), behaves, "img", "/probe", cases, &out)
	if err != nil || failures != 0 {
		t.Fatalf("Run = %d, %v\n%s", failures, err, out.String())
	}
	if strings.Count(out.String(), "✓") != len(cases) {
		t.Errorf("not every row reported:\n%s", out.String())
	}

	refusesEverything := func(context.Context, []string) (string, bool, error) {
		return "REFUSED\nno\n", false, nil
	}
	out.Reset()
	failures, err = Run(context.Background(), refusesEverything, "img", "/probe", cases, &out)
	if err != nil {
		t.Fatal(err)
	}
	// The two pass rows fail on the verdict, every refusal on its needle.
	if failures != len(cases) || !strings.Contains(out.String(), "got REFUSED, expected PASS") ||
		!strings.Contains(out.String(), "did not mention") || !strings.Contains(out.String(), "    no") {
		t.Errorf("Run over a guard that refuses everything = %d failures:\n%s", failures, out.String())
	}

	broken := func(context.Context, []string) (string, bool, error) { return "", false, errors.New("no runtime") }
	var rowErr *RowError
	if _, err := Run(context.Background(), broken, "img", "/probe", cases, &out); !errors.As(err, &rowErr) || rowErr.Unwrap() == nil {
		t.Fatalf("Run over a broken runtime = %v, want a RowError", err)
	}
	if !strings.Contains(rowErr.Error(), cases[0].Name) {
		t.Errorf("RowError = %q", rowErr)
	}
}

func fakeHost() Host {
	return Host{
		Ready:        func(context.Context) error { return nil },
		DeviceExists: func(string) bool { return true },
		BuildProbe: func(_ context.Context, out string) error {
			return os.WriteFile(out, []byte("probe"), 0o600)
		},
		Container: func(ctx context.Context, args []string) (string, bool, error) {
			for i, arg := range args {
				if arg == "-v" && strings.HasSuffix(args[i+1], ":/preflight-probe:ro") {
					mode := args[len(args)-1]
					if mode == ModeNetAdmin && slices.Contains(args, "NET_ADMIN") && !slices.Contains(args, "SYS_ADMIN") {
						return "PASS\n", true, nil
					}
					if mode == ModeDMKeyring && slices.Contains(args, "SYS_ADMIN") && slices.Contains(args, "--device") && slices.ContainsFunc(args, func(a string) bool {
						return strings.HasSuffix(a, "/narrow.json")
					}) && !slices.Contains(args, "65534") {
						return "PASS\n", true, nil
					}
					var needles []string
					for _, c := range Cases(Profiles{}) {
						needles = append(needles, c.Needle)
					}
					return "REFUSED\n" + strings.Join(needles, " ") + "\n", false, nil
				}
			}
			return "", false, errors.New("the probe was not mounted")
		},
	}
}

func TestMainRunsTheMatrix(t *testing.T) {
	var out bytes.Buffer
	if err := Main(context.Background(), fakeHost(), "img", &out); err != nil {
		t.Fatalf("Main = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "the guard refuses every misconfigured container") {
		t.Errorf("output:\n%s", out.String())
	}

	host := fakeHost()
	host.Container = func(context.Context, []string) (string, bool, error) { return "PASS\n", true, nil }
	if err := Main(context.Background(), host, "img", &out); !errors.Is(err, ErrRowsFailed) {
		t.Fatalf("Main over a guard that passes everything = %v, want ErrRowsFailed", err)
	}
	host.Container = func(context.Context, []string) (string, bool, error) { return "", false, errors.New("gone") }
	var rowErr *RowError
	if err := Main(context.Background(), host, "img", &out); !errors.As(err, &rowErr) {
		t.Fatalf("Main over a broken runtime = %v, want a RowError", err)
	}
}

func TestMainStopsOnAMissingPrerequisite(t *testing.T) {
	notReady := errors.New("no docker")
	host := fakeHost()
	host.Ready = func(context.Context) error { return notReady }
	if err := Main(context.Background(), host, "img", &bytes.Buffer{}); !errors.Is(err, notReady) {
		t.Fatalf("Main without a runtime = %v", err)
	}

	host = fakeHost()
	host.DeviceExists = func(string) bool { return false }
	var prereq *PrerequisiteError
	if err := Main(context.Background(), host, "img", &bytes.Buffer{}); !errors.As(err, &prereq) ||
		!strings.Contains(err.Error(), DeviceMapperControl) {
		t.Fatalf("Main without the control node = %v, want a PrerequisiteError naming it", err)
	}

	host = fakeHost()
	buildFailed := &BuildError{Output: "syntax error", Err: errors.New("exit status 1")}
	host.BuildProbe = func(context.Context, string) error { return buildFailed }
	if err := Main(context.Background(), host, "img", &bytes.Buffer{}); !errors.Is(err, buildFailed) {
		t.Fatalf("Main with a failed build = %v", err)
	}
	if !strings.Contains(buildFailed.Error(), "syntax error") || buildFailed.Unwrap() == nil {
		t.Errorf("BuildError = %q", buildFailed)
	}
}

func TestDockerHostPrerequisites(t *testing.T) {
	ctx := context.Background()
	var prereq *PrerequisiteError
	if err := DockerHost("no-such-runtime-binary").Ready(ctx); !errors.As(err, &prereq) || prereq.Unwrap() == nil {
		t.Fatalf("Ready with no runtime = %v, want a PrerequisiteError", err)
	}
	if err := DockerHost("false").Ready(ctx); !errors.As(err, &prereq) || !strings.Contains(err.Error(), "cannot talk") {
		t.Fatalf("Ready with a runtime that will not answer = %v, want a PrerequisiteError", err)
	}
	if err := DockerHost("true").Ready(ctx); err != nil {
		t.Fatalf("Ready with a runtime that answers = %v", err)
	}
	if (&PrerequisiteError{What: "x"}).Error() != "preflightmatrix: x" {
		t.Error("PrerequisiteError text")
	}

	host := DockerHost("true")
	if !host.DeviceExists(t.TempDir()) || host.DeviceExists(filepath.Join(t.TempDir(), "absent")) {
		t.Error("DeviceExists does not tell present from absent")
	}
}

func TestDockerHostContainer(t *testing.T) {
	ctx := context.Background()
	if out, passed, err := DockerHost("true").Container(ctx, []string{"run"}); err != nil || !passed || out != "" {
		t.Fatalf("a zero exit = %q, %v, %v; want a pass", out, passed, err)
	}
	if _, passed, err := DockerHost("false").Container(ctx, []string{"run"}); err != nil || passed {
		t.Fatalf("a non-zero exit = %v, %v; want a refusal, not an error", passed, err)
	}
	if _, _, err := DockerHost("no-such-runtime-binary").Container(ctx, nil); err == nil {
		t.Fatal("a runtime that cannot start must be an error, not a verdict")
	}
}

// TestDockerHostBuildsTheProbe builds the real probe from the module root, and
// proves a build that fails stops the matrix.
func TestDockerHostBuildsTheProbe(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe")
	t.Chdir(filepath.Join("..", ".."))
	if err := DockerHost("true").BuildProbe(context.Background(), out); err != nil {
		t.Fatalf("BuildProbe: %v", err)
	}
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("no probe binary: %v", err)
	}

	t.Chdir(t.TempDir())
	var buildErr *BuildError
	if err := DockerHost("true").BuildProbe(context.Background(), out); !errors.As(err, &buildErr) {
		t.Fatalf("BuildProbe outside the module = %v, want a BuildError", err)
	}
}
