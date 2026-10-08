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

package guards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden fixtures prove each custody rule can fire and each near-miss is
// left alone. What is here is the rest: the paths that decide whether the
// scanner is still looking at the model it claims to enforce, driven against
// trees these tests build and own.

// writeTree lays out files under root from a map of relative path to content.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
}

// anchorOnly is a stand-in internal/luks whose FileKeyProvider borrows once —
// the anchor as the scanner expects to find it.
const anchorOnly = `package luks

import "github.com/jeremyhahn/go-enclave"

func FileKeyProvider(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func([]byte) error { return nil })
}
`

// TestCustodyEveryBorrowWindowIsReal keeps borrowWindows honest against the
// tree it describes.
//
// An entry naming a function that no longer borrows is an exemption waiting
// for something to wear it: rename FileKeyProvider, add a WithBytes call under the old
// name somewhere else, and a stale entry would let it through. So every entry
// has to correspond to a site the scan actually met, and the anchor to exactly
// one.
func TestCustodyEveryBorrowWindowIsReal(t *testing.T) {
	_, evidence, err := scanCustody(repoRoot(t))
	if err != nil {
		t.Fatalf("scanning the repository: %v", err)
	}

	for _, window := range borrowWindows {
		seen := evidence.windowsSeen[window.Dir+":"+window.Func]
		if seen == 0 {
			t.Errorf("borrowWindows names %s.%s, which the scan met no WithBytes call in — the entry is a stale exemption; remove it or re-point it",
				window.Dir, window.Func)
		}
		t.Logf("%s.%s: %d borrow(s) — %s", window.Dir, window.Func, seen, window.Why)
	}
	if got := evidence.windowsSeen[anchorWindow.Dir+":"+anchorWindow.Func]; got != 1 {
		t.Errorf("the anchor %s.%s borrows %d time(s), want exactly 1", anchorWindow.Dir, anchorWindow.Func, got)
	}
}

// TestCustodyLosingTheAnchorIsNotAPass is rule 1's fail-closed half.
//
// If FileKeyProvider stops calling WithBytes while the tree still borrows
// elsewhere, the window table is being checked against nothing, and a scanner
// in that state must say so at the anchor rather than report the tree clean.
// If FileKeyProvider is gone altogether, the scanner has nothing to anchor on
// and the scan itself fails.
func TestCustodyLosingTheAnchorIsNotAPass(t *testing.T) {
	t.Run("the anchor no longer borrows", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{
			"internal/luks/key.go": `package luks

import "github.com/jeremyhahn/go-enclave"

func FileKeyProvider() error {
	return nil
}

func StaticKeyProvider(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func([]byte) error { return nil })
}
`,
		})

		result, err := KeyMaterialCustody().Scan(root)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		var atAnchor bool
		for _, finding := range result.Findings {
			if finding.File == "internal/luks/key.go" && finding.Line == 5 &&
				strings.Contains(finding.Message, "exactly once") {
				atAnchor = true
			}
		}
		if !atAnchor {
			t.Errorf("the anchor borrows zero times and the scan did not say so at its declaration: %v", result.Findings)
		}
	})

	t.Run("the anchor borrows twice", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{
			"internal/luks/key.go": `package luks

import "github.com/jeremyhahn/go-enclave"

func FileKeyProvider(enc *enclave.MemoryEnclave) error {
	if err := enc.WithBytes(func([]byte) error { return nil }); err != nil {
		return err
	}
	return enc.WithBytes(func([]byte) error { return nil })
}
`,
		})

		result, err := KeyMaterialCustody().Scan(root)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(result.Findings) != 1 || result.Findings[0].Line != 5 {
			t.Errorf("the anchor borrows twice; want one finding at its declaration, got %v", result.Findings)
		}
	})

	t.Run("the anchor does not exist", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{
			"pkg/other/other.go": `package other

import "github.com/jeremyhahn/go-enclave"

func Borrow(enc *enclave.MemoryEnclave) error {
	return enc.WithBytes(func([]byte) error { return nil })
}
`,
		})

		_, err := KeyMaterialCustody().Scan(root)
		if err == nil {
			t.Fatal("a tree that borrows from enclaves with no FileKeyProvider anywhere scanned as if the anchor were present")
		}
		if !strings.Contains(err.Error(), "anchored") {
			t.Errorf("the error does not say the anchor is missing: %v", err)
		}
	})

	t.Run("a tree with no borrows needs no anchor", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{"pkg/other/other.go": "package other\n\nfunc F() {}\n"})

		result, err := KeyMaterialCustody().Scan(root)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("fired on a tree with no enclaves: %v", result.Findings)
		}
		if len(result.Examined) != 1 {
			t.Errorf("examined %v, want the one file", result.Examined)
		}
	})
}

// TestCustodyWithKeyIsNotABorrowWindow pins the design decision the table
// states: the passphrase is lent to the Backend as an enclave, so withKey
// reading it out with WithBytes is a finding even though it sits in the
// package that owns the model.
func TestCustodyWithKeyIsNotABorrowWindow(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"internal/luks/manager.go": anchorOnly + `
type Manager struct{ enc *enclave.MemoryEnclave }

func (m *Manager) withKey(op func(key []byte) error) error {
	return m.enc.WithBytes(op)
}
`,
	})

	result, err := KeyMaterialCustody().Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var found bool
	for _, finding := range result.Findings {
		if strings.Contains(finding.Message, "from internal/luks.(*Manager).withKey") {
			found = true
		}
	}
	if !found {
		t.Errorf("a WithBytes in withKey was not reported: %v", result.Findings)
	}
}

// TestCustodyAFileNoConfigurationSelectsIsAScanFailure keeps the type-checked
// scanner from failing open on the file most likely to be unusual.
//
// The text scanners read every file whatever its build tags say. This one
// cannot — it needs a consistent package — so instead it refuses to report a
// tree clean while a file went unread.
func TestCustodyAFileNoConfigurationSelectsIsAScanFailure(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"pkg/p/p.go":       "package p\n\nfunc F() {}\n",
		"pkg/p/p_plan9.go": "//go:build plan9\n\npackage p\n\nfunc G() {}\n",
	})

	_, err := KeyMaterialCustody().Scan(root)
	if err == nil {
		t.Fatal("a file no configuration selects was left unread and the scan reported success")
	}
	if !strings.Contains(err.Error(), "p_plan9.go") {
		t.Errorf("the error does not name the unread file: %v", err)
	}
}

// TestCustodyATypeErrorIsAScanFailure: the rules are keyed on types, so a
// package whose types could not be resolved is a package the rules cannot see
// into, and that is a failure rather than a clean result.
func TestCustodyATypeErrorIsAScanFailure(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"pkg/p/p.go": "package p\n\nfunc F() { undefinedThing() }\n",
	})

	_, err := KeyMaterialCustody().Scan(root)
	if err == nil {
		t.Fatal("a package that does not type-check scanned as clean")
	}
	if !strings.Contains(err.Error(), "type-check") {
		t.Errorf("the error does not say the type-check failed: %v", err)
	}
}

// TestCustodyExaminesEveryConfigurationsFiles pins the reason there are two
// build configurations: a `!linux` stub is read, and read once.
func TestCustodyExaminesEveryConfigurationsFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"pkg/p/p_linux.go": "//go:build linux\n\npackage p\n\nfunc F() {}\n",
		"pkg/p/p_other.go": "//go:build !linux\n\npackage p\n\nfunc F() {}\n",
	})

	result, err := KeyMaterialCustody().Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"pkg/p/p_linux.go", "pkg/p/p_other.go"}
	if strings.Join(result.Examined, ",") != strings.Join(want, ",") {
		t.Errorf("examined %v, want %v", result.Examined, want)
	}
}

// TestCustodyATreeWhoseOnlyBorrowIsTheAnchorIsClean is the anchor path's
// positive control: an anchor that borrows exactly once is what the model
// looks like, and it produces nothing.
func TestCustodyATreeWhoseOnlyBorrowIsTheAnchorIsClean(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"internal/luks/manager.go": anchorOnly})

	result, err := KeyMaterialCustody().Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("a tree whose only borrow is the anchor is clean; got %v", result.Findings)
	}
}

// TestCustodyMaterialNames is the rule-4 name boundary, spelled out one case
// per line so the refinement in the scanner's documentation is what the code
// does.
func TestCustodyMaterialNames(t *testing.T) {
	cases := []struct {
		name     string
		isString bool
		want     bool
	}{
		{"key", false, true},
		{"key", true, false}, // a key/value key
		{"luksKey", true, true},
		{"apiKey", true, true},
		{"passphrase", true, true},
		{"passphrase", false, true},
		{"secret", true, true},
		{"password", true, true},
		{"token", true, true},
		{"rootPassword", true, true},
		{"ROOT_PASSWORD", true, true},
		{"sharedSecret", false, true},
		{"luksKeyBytes", false, true},
		{"secretData", false, true},
		{"keyMaterial", false, true},
		{"keyPath", true, false},
		{"keyFile", true, false},
		{"luksKeyFile", true, false},
		{"tokenID", true, false},
		{"secretName", true, false},
		{"passwordHash", false, false},
		{"keyLength", true, false},
		{"monkey", true, false}, // a word ending in "key" is not the word key
		{"keys", true, false},
		{"", true, false},
		{"_", true, false},
	}
	for _, tc := range cases {
		if got := isMaterialName(tc.name, tc.isString); got != tc.want {
			t.Errorf("isMaterialName(%q, string=%v) = %v, want %v (words %v)", tc.name, tc.isString, got, tc.want, splitWords(tc.name))
		}
	}
}

// TestCustodySplitWords pins the identifier splitter, whose boundaries are
// what make keyPath and luksKeyFile non-matches.
func TestCustodySplitWords(t *testing.T) {
	cases := map[string]string{
		"key":           "key",
		"keyPath":       "key path",
		"luksKeyFile":   "luks key file",
		"tokenID":       "token id",
		"HTTPKey":       "http key",
		"ROOT_PASSWORD": "root password",
		"root_password": "root password",
		"key2":          "key2",
		"Key":           "key",
	}
	for name, want := range cases {
		if got := strings.Join(splitWords(name), " "); got != want {
			t.Errorf("splitWords(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestCustodyFuncDeclNames pins the form borrowWindows entries are written in.
func TestCustodyFuncDeclNames(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"pkg/p/p.go": `package p

import "github.com/jeremyhahn/go-enclave"

type T struct{}
type G[X any] struct{}

func F(enc *enclave.MemoryEnclave) error         { return enc.WithBytes(nil) }
func (T) M(enc *enclave.MemoryEnclave) error     { return enc.WithBytes(nil) }
func (*T) P(enc *enclave.MemoryEnclave) error    { return enc.WithBytes(nil) }
func (G[X]) Q(enc *enclave.MemoryEnclave) error  { return enc.WithBytes(nil) }
func (*G[X]) R(enc *enclave.MemoryEnclave) error { return enc.WithBytes(nil) }
`,
		"internal/luks/manager.go": anchorOnly,
	})

	result, err := KeyMaterialCustody().Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"pkg/p.F,", "pkg/p.T.M,", "pkg/p.(*T).P,", "pkg/p.G.Q,", "pkg/p.(*G).R,"}
	for _, name := range want {
		var found bool
		for _, finding := range result.Findings {
			if strings.Contains(finding.Message, "from "+name) {
				found = true
			}
		}
		if !found {
			t.Errorf("no finding names the borrowing function %q: %v", name, result.Findings)
		}
	}
}
