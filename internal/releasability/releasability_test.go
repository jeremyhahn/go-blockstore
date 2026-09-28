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

package releasability

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Every lab value in this file is built by concatenation, so that the gate —
// which scans this file like any other — does not find the samples it is
// being tested on.
var (
	labIP      = "10.20." + "30.40"
	labCIDR    = "192.168." + "7.0/24"
	labHost    = "vsta" + "tion-01"
	ownerPath  = "/home/" + "jh" + "ahn/src"
	pemPrivate = "-----BEGIN " + "RSA PRIVATE KEY-----"
)

// git runs git in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRepo creates a git repository holding files, all added to the index.
func newRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-q")
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git(t, root, "add", "-A")
	return root
}

// findingsFor returns the rules reported against path.
func findingsFor(result Result, path string) map[Rule]int {
	rules := map[Rule]int{}
	for _, f := range result.Findings {
		if f.Path == path {
			rules[f.Rule]++
		}
	}
	return rules
}

// TestTheRepositoryIsPubliclyReleasable is the gate over this repository, so
// `make test` enforces it as well as `make lint` and the CI Lint step.
func TestTheRepositoryIsPubliclyReleasable(t *testing.T) {
	root, err := Root(".")
	if err != nil {
		t.Fatalf("locating the repository: %v", err)
	}
	result, err := ScanRepo(root)
	if result.Examined == 0 {
		t.Fatalf("the gate examined no files: %v", err)
	}
	for _, f := range result.Findings {
		t.Errorf("%s", f)
	}
	if err != nil && !errors.Is(err, ErrFindings) {
		t.Fatalf("the scan itself failed, which is not a pass: %v", err)
	}
}

// TestContentRulesFire proves every content rule can say yes, one sample per
// spelling, so losing a spelling fails here rather than going quiet.
func TestContentRulesFire(t *testing.T) {
	cases := []struct {
		line string
		rule Rule
		want string
	}{
		{"dial " + labIP + ":7792", RuleLabAddress, labIP},
		{"route " + labCIDR, RuleLabAddress, "192.168." + "7.0"},
		{"peer 172.20." + "1.1", RuleLabAddress, "172.20." + "1.1"},
		{"the lab subnet 192.168." + "101.x", RuleLabAddress, "192.168." + "101"},
		{"public 23.143." + "36.9", RuleLabAddress, "23.143." + "36.9"},
		{"v6 2602:F5" + "BB::1", RuleLabAddress, "2602:F5" + "BB"},
		{"forge.example" + ".INTERNAL", RuleInternalDomain, "forge.example" + ".INTERNAL"},
		{"nas" + ".lan", RuleInternalDomain, "nas" + ".lan"},
		{"printer" + ".home.arpa", RuleInternalDomain, "printer" + ".home.arpa"},
		{"box" + ".localdomain", RuleInternalDomain, "box" + ".localdomain"},
		{"ssh " + labHost, RuleLabHost, labHost},
		{"DELL" + "EMC-02 pair", RuleLabHost, "DELL" + "EMC-02"},
		{"the dell" + "emc pair", RuleLabHost, "dell" + "emc"},
		{"on God" + "like", RuleLabHost, "God" + "like"},
		{"mon" + "0 is down", RuleLabHost, "mon" + "0"},
		{"mini" + "-03", RuleLabHost, "mini" + "-03"},
		{"rack1" + "swt Gi1/0/36", RuleLabHost, "rack1" + "swt"},
		{"cd " + ownerPath, RuleOwnerPath, "jh" + "ahn"},
		{"/Users/" + "JH" + "ahn", RuleOwnerPath, "JH" + "ahn"},
		{"/mnt/vs" + "tation-01/x", RuleOwnerPath, "/mnt/vs" + "tation"},
		{pemPrivate, RuleCertTooling, pemPrivate},
		{"-----BEGIN " + "CERTIFICATE-----", RuleCertTooling, "-----BEGIN " + "CERTIFICATE-----"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			findings := scanText("f.txt", "first line\n"+tc.line)
			for _, f := range findings {
				if f.Rule == tc.rule && f.Match == tc.want && f.Line == 2 {
					return
				}
			}
			t.Fatalf("scanText(%q) = %v, want a %s finding matching %q on line 2", tc.line, findings, tc.rule, tc.want)
		})
	}
}

// TestContentRulesStayQuiet is the other half: a gate that fires on ordinary
// text is switched off within a week.
func TestContentRulesStayQuiet(t *testing.T) {
	for _, line := range []string{
		"address ipv4 192.0.2.1:7792;",
		"docs 198.51.100.7 and 203.0.113.9",
		"an OID 1.3.6.10.0.0.1 is one run",
		"version v1.10.0 and 10.4.2",
		"not an address 300.1.1.1",
		"github.com/jeremyhahn/go-blockstore/internal/guards",
		"mount at /mnt/data",
		"monitor0 and mini-cluster",
		"Dell EMC PowerEdge",
		"example.com and node-a.example",
		"2001:db8::1",
		"-----BEGIN PGP SIGNATURE-----",
	} {
		if findings := scanText("f.txt", line); len(findings) != 0 {
			t.Errorf("scanText(%q) = %v, want nothing", line, findings)
		}
	}
}

func TestShebangShell(t *testing.T) {
	cases := map[string]string{
		"#!/bin/sh\necho":             "sh",
		"#!/usr/bin/env bash":         "bash",
		"#! /bin/bash -e":             "bash",
		"#!/usr/bin/env -S bash -eu":  "bash",
		"#!/usr/bin/env FOO=1 zsh":    "zsh",
		"#!/bin/busybox sh":           "sh",
		"#!/bin/DASH":                 "DASH",
		"#!/usr/bin/python3\nprint()": "",
		"#!/usr/bin/env python3":      "",
		"#!/usr/bin/env":              "",
		"#!":                          "",
		"package main\n#!/bin/sh":     "",
		"":                            "",
	}
	for content, want := range cases {
		if got := shebangShell([]byte(content)); got != want {
			t.Errorf("shebangShell(%q) = %q, want %q", content, got, want)
		}
	}
}

func TestIsAgentFile(t *testing.T) {
	cases := map[string]bool{
		".claude/settings.json":   true,
		"sub/.Serena/project.yml": true,
		".cursor/rules":           true,
		"CLAUDE.md":               true,
		"docs/AGENTS.md":          true,
		"GEMINI.md":               true,
		".cursorrules":            true,
		"README.md":               false,
		"claude.md.txt":           false,
		"cmd/claude/main.go":      false,
	}
	for name, want := range cases {
		if got := isAgentFile(name); got != want {
			t.Errorf("isAgentFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsCertTooling(t *testing.T) {
	cases := map[string]bool{
		"certs/ca.pem":     true,
		"tls/server.CRT":   true,
		"server.key":       true,
		"bundle.p12":       true,
		"etc/openssl.cnf":  true,
		"pkg/keys/keys.go": false,
		"docs/keyring.md":  false,
	}
	for name, want := range cases {
		if got := isCertTooling(name); got != want {
			t.Errorf("isCertTooling(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestScanRefusesEachFileRule plants one violation per file-level rule in a
// real git repository and requires each to be reported against its file.
func TestScanRefusesEachFileRule(t *testing.T) {
	root := newRepo(t, map[string]string{
		"README.md":             "# clean\n\nA clean file.\n",
		"docs/deploy.md":        "connect to " + labIP + "\n",
		"tools/build.sh":        "echo hi\n",
		"tools/build":           "#!/usr/bin/env bash\necho hi\n",
		".claude/settings.json": "{}\n",
		"CLAUDE.md":             "notes\n",
		"certs/ca.pem":          "not really\n",
		"pkg/x/key.go":          "const k = `" + pemPrivate + "`\n",
	})
	result, err := ScanRepo(root)
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("ScanRepo = %v, want ErrFindings", err)
	}
	if result.Examined != 8 {
		t.Errorf("Examined = %d, want 8", result.Examined)
	}
	want := map[string]Rule{
		"docs/deploy.md":        RuleLabAddress,
		"tools/build.sh":        RuleShellScript,
		"tools/build":           RuleShellScript,
		".claude/settings.json": RuleAgentFile,
		"CLAUDE.md":             RuleAgentFile,
		"certs/ca.pem":          RuleCertTooling,
		"pkg/x/key.go":          RuleCertTooling,
	}
	for path, rule := range want {
		if findingsFor(result, path)[rule] == 0 {
			t.Errorf("%s: no %s finding in %v", path, rule, result.Findings)
		}
	}
	if got := findingsFor(result, "README.md"); len(got) != 0 {
		t.Errorf("README.md is clean but drew %v", got)
	}
}

// TestScanReadsSymlinkTargetsWithoutFollowingThem: the target TEXT is what is
// published, and the content behind it is on one machine only.
func TestScanReadsSymlinkTargetsWithoutFollowingThem(t *testing.T) {
	root := newRepo(t, map[string]string{"inner.txt": "clean\n"})
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret "+labIP+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"to-owner":   ownerPath,
		"to-outside": outside,
		"up":         "../elsewhere",
		"to-inner":   "inner.txt",
		"sub/back":   "../inner.txt",
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	git(t, root, "add", "-A")

	result, err := ScanRepo(root)
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("ScanRepo = %v, want ErrFindings", err)
	}
	if got := findingsFor(result, "to-owner"); got[RuleOwnerPath] == 0 || got[RuleSymlinkEscape] == 0 {
		t.Errorf("to-owner = %v, want owner-path and symlink-escape", got)
	}
	if got := findingsFor(result, "to-outside"); got[RuleSymlinkEscape] == 0 || got[RuleLabAddress] != 0 {
		t.Errorf("to-outside = %v, want symlink-escape and NOT the lab address behind it (never followed)", got)
	}
	if got := findingsFor(result, "up"); got[RuleSymlinkEscape] == 0 {
		t.Errorf("up = %v, want symlink-escape", got)
	}
	for _, name := range []string{"to-inner", "sub/back"} {
		if got := findingsFor(result, name); len(got) != 0 {
			t.Errorf("%s points inside the tree but drew %v", name, got)
		}
	}
}

// TestScanFailsClosedOnWhatItCannotRead: nothing unread passes silently.
func TestScanFailsClosedOnWhatItCannotRead(t *testing.T) {
	big := strings.Repeat("a", MaxFileSize+1)
	root := newRepo(t, map[string]string{
		"blob.bin": "\x00\x01binary",
		"late.bin": strings.Repeat("x", binarySniff) + "\x00",
		"huge.txt": big,
		"gone.txt": "deleted after add\n",
		"text.txt": "fine\n",
	})
	if err := os.Remove(filepath.Join(root, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	// A submodule: a gitlink in the index and a directory in the tree.
	sha := strings.Repeat("a", 40)
	git(t, root, "update-index", "--add", "--cacheinfo", "160000,"+sha+",vendored")
	if err := os.Mkdir(filepath.Join(root, "vendored"), 0o750); err != nil {
		t.Fatal(err)
	}
	// A special file under a tracked name.
	blob := git(t, root, "hash-object", "-w", filepath.Join(root, "text.txt"))
	git(t, root, "update-index", "--add", "--cacheinfo", "100644,"+blob+",pipe")
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ScanRepo(root)
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("ScanRepo = %v, want ErrFindings", err)
	}
	for _, name := range []string{"blob.bin", "huge.txt", "gone.txt", "vendored", "pipe"} {
		if findingsFor(result, name)[RuleUnreadable] == 0 {
			t.Errorf("%s was not read and drew no unreadable finding: %v", name, result.Findings)
		}
	}
	// A NUL past the sniff window is text by git's own rule, and is read.
	if got := findingsFor(result, "late.bin"); len(got) != 0 {
		t.Errorf("late.bin has its NUL past %d bytes, so it is text; drew %v", binarySniff, got)
	}
	if got := findingsFor(result, "text.txt"); len(got) != 0 {
		t.Errorf("text.txt drew %v", got)
	}
}

// TestExemptionsAcceptOnlyUnreadableFiles: an exemption says why an unread
// file ships, and nothing else.
func TestExemptionsAcceptOnlyUnreadableFiles(t *testing.T) {
	root := newRepo(t, map[string]string{
		"logo.png":   "\x89PNG\x00\x00",
		"payload.sh": "\x00binary but still a script by name",
		"text.txt":   "fine\n",
		ExemptFile: "# comment\n\nlogo.png  the project logo, a binary image\n" +
			"payload.sh\tpretending\n" +
			"text.txt readable anyway\n" +
			"absent.bin not tracked at all\n",
	})
	result, err := ScanRepo(root)
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("ScanRepo = %v, want ErrFindings", err)
	}
	if result.Exempted != 2 {
		t.Errorf("Exempted = %d, want 2 (logo.png, payload.sh's unreadability)", result.Exempted)
	}
	if got := findingsFor(result, "logo.png"); len(got) != 0 {
		t.Errorf("logo.png is exempt but drew %v", got)
	}
	if got := findingsFor(result, "payload.sh"); got[RuleShellScript] == 0 || got[RuleUnreadable] != 0 {
		t.Errorf("payload.sh = %v, want shell-script only: an exemption cannot excuse a script", got)
	}
	stale := map[string]bool{}
	for _, f := range result.Findings {
		if f.Rule == RuleStaleExemption {
			stale[f.Match] = true
		}
	}
	if !stale["text.txt"] || !stale["absent.bin"] || len(stale) != 2 {
		t.Errorf("stale exemptions = %v, want exactly text.txt and absent.bin", stale)
	}
}

func TestScanIsCleanOnACleanTree(t *testing.T) {
	root := newRepo(t, map[string]string{
		"README.md": "Use 192.0.2.1 and node-a.example.\n",
		"logo.png":  "\x00png",
		ExemptFile:  "logo.png  the logo\n",
	})
	result, err := ScanRepo(root)
	if err != nil {
		t.Fatalf("ScanRepo = %v, findings %v", err, result.Findings)
	}
	if result.Examined != 3 || result.Exempted != 1 {
		t.Errorf("Examined, Exempted = %d, %d, want 3, 1", result.Examined, result.Exempted)
	}
}

func TestScanRefusesAnEmptyFileList(t *testing.T) {
	if _, err := Scan(t.TempDir(), nil, nil); !errors.Is(err, ErrNothingExamined) {
		t.Fatalf("Scan over nothing = %v, want ErrNothingExamined", err)
	}
	root := newRepo(t, nil)
	if _, err := ScanRepo(root); !errors.Is(err, ErrNothingExamined) {
		t.Fatalf("ScanRepo over an empty index = %v, want ErrNothingExamined", err)
	}
}

func TestParseExemptionsRefusesWhatItCannotTrust(t *testing.T) {
	for name, content := range map[string]string{
		"no reason":    "logo.png\n",
		"blank reason": "logo.png   \t \n",
		"duplicate":    "a.bin one\na.bin two\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseExemptions(strings.NewReader(content))
			var exemptionErr *ExemptionError
			if !errors.As(err, &exemptionErr) || exemptionErr.Line == 0 {
				t.Fatalf("ParseExemptions(%q) = %v, want an ExemptionError with a line", content, err)
			}
			if !strings.Contains(err.Error(), ExemptFile+":") {
				t.Errorf("error %q does not name the file and line", err)
			}
		})
	}
}

func TestLoadExemptions(t *testing.T) {
	missing, err := LoadExemptions(t.TempDir())
	if err != nil || len(missing) != 0 {
		t.Fatalf("LoadExemptions with no file = %v, %v; want an empty list", missing, err)
	}

	dir := t.TempDir()
	if mkErr := os.Mkdir(filepath.Join(dir, ExemptFile), 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	_, err = LoadExemptions(dir)
	var exemptionErr *ExemptionError
	if !errors.As(err, &exemptionErr) || exemptionErr.Err == nil {
		t.Fatalf("LoadExemptions over a directory = %v, want an ExemptionError wrapping the read failure", err)
	}

	root := newRepo(t, map[string]string{"a.txt": "x\n", ExemptFile: "a.txt\n"})
	if _, err := ScanRepo(root); !errors.As(err, &exemptionErr) {
		t.Fatalf("ScanRepo with a reasonless exemption = %v, want an ExemptionError", err)
	}
}

func TestLoadExemptionsSurfacesAnUnopenableFile(t *testing.T) {
	dir := t.TempDir()
	// A symlink loop cannot be opened, and is not "missing".
	if err := os.Symlink(ExemptFile, filepath.Join(dir, ExemptFile)); err != nil {
		t.Fatal(err)
	}
	_, err := LoadExemptions(dir)
	var exemptionErr *ExemptionError
	if !errors.As(err, &exemptionErr) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadExemptions over a symlink loop = %v, want an ExemptionError", err)
	}
}

func TestLoadExemptionsRefusesAMissingRoot(t *testing.T) {
	_, err := LoadExemptions(filepath.Join(t.TempDir(), "absent"))
	var exemptionErr *ExemptionError
	if !errors.As(err, &exemptionErr) || exemptionErr.Err == nil {
		t.Fatalf("LoadExemptions under a missing root = %v, want an ExemptionError, not an empty list", err)
	}
}

func TestOutsideARepositoryIsAListError(t *testing.T) {
	dir := t.TempDir()
	var listErr *ListError
	if _, err := Root(dir); !errors.As(err, &listErr) {
		t.Fatalf("Root outside a repository = %v, want a ListError", err)
	}
	if _, err := TrackedFiles(dir); !errors.As(err, &listErr) {
		t.Fatalf("TrackedFiles outside a repository = %v, want a ListError", err)
	}
	if _, err := ScanRepo(dir); !errors.As(err, &listErr) || listErr.Unwrap() == nil {
		t.Fatalf("ScanRepo outside a repository = %v, want a ListError", err)
	}
	if !strings.Contains(listErr.Error(), dir) {
		t.Errorf("ListError %q does not name the directory", listErr)
	}
}

func TestReport(t *testing.T) {
	var clean bytes.Buffer
	if err := Report(&clean, Result{Examined: 7}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clean.String(), "examined 7 tracked file(s)") || !strings.Contains(clean.String(), "clean") {
		t.Errorf("clean report = %q", clean.String())
	}

	var dirty bytes.Buffer
	result := Result{Examined: 2, Findings: []Finding{
		{Path: "a.md", Line: 3, Rule: RuleLabAddress, Match: "m", Message: "do this"},
		{Path: "b.sh", Rule: RuleShellScript, Message: "go only"},
	}}
	if err := Report(&dirty, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 finding(s)", `a.md:3: [lab-address] "m" -- do this`, "b.sh: [shell-script] go only", "docs/release/public-releasability.md"} {
		if !strings.Contains(dirty.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, dirty.String())
		}
	}

	var reportErr *ReportError
	if err := Report(failingWriter{}, result); !errors.As(err, &reportErr) || reportErr.Unwrap() == nil {
		t.Fatalf("Report to a failing writer = %v, want a ReportError", err)
	}
	if !strings.Contains(reportErr.Error(), "writing the report") {
		t.Errorf("ReportError = %q", reportErr)
	}
}

func TestExcerptBoundsLongLines(t *testing.T) {
	long := strings.Repeat("x", excerptLimit+50)
	if got := excerpt("  " + long); len(got) != excerptLimit+len(" ...") {
		t.Errorf("excerpt length = %d, want %d", len(got), excerptLimit+len(" ..."))
	}
	if got := excerpt("  short  "); got != "short" {
		t.Errorf("excerpt = %q, want %q", got, "short")
	}
}

func TestExemptionErrorText(t *testing.T) {
	whole := &ExemptionError{Reason: "cannot be read", Err: errors.New("boom")}
	if got := whole.Error(); got != "releasability: "+ExemptFile+": cannot be read: boom" {
		t.Errorf("Error() = %q", got)
	}
	if !errors.Is(whole, whole.Err) {
		t.Error("ExemptionError does not unwrap")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
