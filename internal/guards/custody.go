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
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// enclavePackage is where the locked-memory primitive lives. Rule 1 is stated
// against ITS MemoryEnclave and no other type, which is the whole reason this
// scanner resolves types rather than matching names.
const enclavePackage = "github.com/jeremyhahn/go-enclave"

// enclaveType is the type whose methods rule 1 is about.
const enclaveType = "MemoryEnclave"

// luksDir is the custody-owning package, as a path relative to the tree root.
const luksDir = "internal/luks"

// backendType is the interface whose key-taking methods receive the passphrase
// enclave. Only internal/luks may call them, because only internal/luks owns
// the enclave's lifetime.
const backendType = "Backend"

// borrowMethod is the one MemoryEnclave method that exposes the contents at
// all, as a []byte scoped to a callback.
const borrowMethod = "WithBytes"

// keyTakingMethods are the Backend methods that receive the passphrase enclave.
// Close, DataOffset, Mapping and Identity take no key and are not here.
var keyTakingMethods = map[string]struct{}{
	"Format":  {},
	"Open":    {},
	"TestKey": {},
}

// borrowedKeyNames are the []byte parameter names rule 3 treats as a borrowed key.
var borrowedKeyNames = map[string]struct{}{
	"key":        {},
	"passphrase": {},
}

// materialWords are the last words of a name that mark it as key material (rule 4).
var materialWords = map[string]struct{}{
	"key":        {},
	"passphrase": {},
	"secret":     {},
	"password":   {},
	"token":      {},
}

// materialCarriers are trailing words that keep a material name material (keyBytes, secretData).
var materialCarriers = map[string]struct{}{
	"bytes":    {},
	"data":     {},
	"material": {},
}

// borrowWindow names one function that is allowed to call
// MemoryEnclave.WithBytes, and says why.
type borrowWindow struct {
	// Dir is the package directory relative to the tree root.
	Dir string

	// Func is the top-level function in go doc form; closures count as part of it.
	Func string

	// Why is the reason it borrows, for the reader of this table and for the
	// finding a call outside every window produces.
	Why string
}

// borrowWindows lists every function allowed to call WithBytes, with FileKeyProvider as the anchor; (*Manager).withKey is deliberately absent.
var borrowWindows = []borrowWindow{
	{luksDir, "FileKeyProvider", "a fill borrow: the key file's bytes go from the descriptor into locked pages"},
	{luksDir, "StaticKeyProvider", "a clone borrow: locked pages are copied into a fresh enclave's locked pages"},
	{"pkg/drbd", "FileSecretProvider", "a fill borrow: the replication secret file's bytes go into locked pages"},
	{"pkg/drbd", "(*Provider).writeSharedSecret", "the replication secret's read-out window: validated in place and written to the resource file's descriptor"},
}

// anchorWindow is the borrow window whose presence proves the scanner is
// still looking at the right thing. See KeyMaterialCustody.
var anchorWindow = borrowWindows[0]

// custodyBuildConfigs are the build configurations each package is type-checked under; a file none selects is a scan failure.
var custodyBuildConfigs = []struct {
	GOOS string
	Tags []string
}{
	{"linux", []string{"drbd"}},
	{"windows", []string{"drbd"}},
}

// KeyMaterialCustody type-checks the tree and refuses code that takes key material out of the enclave custody model.
// Rules: WithBytes only in borrowWindows; key-taking Backend methods only from internal/luks; a borrowed key only as a direct call argument; no exported key, passphrase, secret, password or token string or []byte parameters.
// Test files are not examined; a type error is a scan failure.
func KeyMaterialCustody() Scanner {
	return Scanner{
		Name: "key-material-custody",
		What: "key material lives in an enclave and is borrowed for one call; nothing copies it out or carries it across a package boundary in the clear",
		Scan: func(root string) (Result, error) {
			result, _, err := scanCustody(root)
			return result, err
		},
	}
}

// custodyEvidence records which borrow windows the scan met, so tests keep borrowWindows honest.
type custodyEvidence struct {
	// windowsSeen counts WithBytes call sites per borrow window, keyed by
	// Dir + ":" + Func.
	windowsSeen map[string]int
}

// scanCustody is the scan, with its evidence exposed for the tests.
func scanCustody(root string) (Result, custodyEvidence, error) {
	evidence := custodyEvidence{windowsSeen: map[string]int{}}

	files, err := walk(root, func(rel string) bool {
		return hasExt(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
	})
	if err != nil {
		return Result{}, evidence, err
	}

	modulePath := custodyModulePath(root)

	// pkg/factory imports the drbd-tagged pkg/drbd, so the importer context gets the tag for the scan and is restored after.
	savedTags := build.Default.BuildTags
	build.Default.BuildTags = append(append([]string(nil), savedTags...), "drbd")
	defer func() { build.Default.BuildTags = savedTags }()

	custodyLoader.Lock()
	defer custodyLoader.Unlock()
	if custodyLoader.fset == nil {
		custodyLoader.fset = token.NewFileSet()
		custodyLoader.imp = importer.ForCompiler(custodyLoader.fset, "source", nil)
	}
	fset := custodyLoader.fset

	var (
		examined  = map[string]struct{}{}
		findings  = map[string]Finding{}
		order     []string
		anchor    = custodyAnchor{}
		typeCheck = types.Config{Importer: custodyLoader.imp}
	)

	// Group the files by directory: a package is a directory, and the type
	// checker wants the whole package at once.
	byDir := map[string][]string{}
	for _, rel := range files {
		dir := path.Dir(rel)
		byDir[dir] = append(byDir[dir], rel)
	}
	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		for _, config := range custodyBuildConfigs {
			ctxt := build.Default
			ctxt.GOOS = config.GOOS
			ctxt.BuildTags = append(append([]string(nil), savedTags...), config.Tags...)

			pkg, err := ctxt.ImportDir(filepathJoin(root, dir), 0)
			if err != nil {
				var none *build.NoGoError
				if errors.As(err, &none) {
					continue
				}
				return Result{}, evidence, fmt.Errorf("custody: reading package %s: %w", dir, err)
			}

			var parsed []*ast.File
			for _, name := range pkg.GoFiles {
				rel := path.Join(dir, name)
				// #nosec G304 -- rel comes from walk over the repository tree.
				file, err := parser.ParseFile(fset, filepathJoin(root, rel), nil, parser.ParseComments)
				if err != nil {
					return Result{}, evidence, err
				}
				parsed = append(parsed, file)
				examined[rel] = struct{}{}
			}
			if len(parsed) == 0 {
				continue
			}

			info := &types.Info{
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			var typeErrors []error
			typeCheck.Error = func(err error) { typeErrors = append(typeErrors, err) }
			pkgPath := modulePath + "/" + dir
			if dir == "." {
				pkgPath = modulePath
			}
			if _, err := typeCheck.Check(pkgPath, fset, parsed, info); err != nil || len(typeErrors) > 0 {
				return Result{}, evidence, fmt.Errorf("custody: %s does not type-check under GOOS=%s tags=%v, so its key material cannot be followed: %w",
					dir, config.GOOS, config.Tags, errors.Join(typeErrors...))
			}

			scan := custodyPackage{
				root:     root,
				dir:      dir,
				fset:     fset,
				info:     info,
				anchor:   &anchor,
				evidence: &evidence,
			}
			for _, file := range parsed {
				for _, finding := range scan.file(file) {
					key := fmt.Sprintf("%s:%d:%s", finding.File, finding.Line, finding.Message)
					if _, dup := findings[key]; !dup {
						findings[key] = finding
						order = append(order, key)
					}
				}
			}
		}
	}

	// A file no configuration selected is a file nobody type-checked, and
	// silence over it would be silence over the file most likely to be
	// unusual. It is a scan failure, and an unreadable file surfaces here too.
	for _, rel := range files {
		if _, read := examined[rel]; read {
			continue
		}
		reason := "excluded by build constraints under every configuration in custodyBuildConfigs"
		// #nosec G304 -- rel comes from walk over the repository tree.
		if handle, err := os.Open(filepathJoin(root, rel)); err != nil {
			reason = err.Error()
		} else {
			_ = handle.Close()
		}
		return Result{}, evidence, fmt.Errorf("custody: %s was not type-checked (%s); add a configuration that selects it rather than leave it unread", rel, reason)
	}

	result := Result{}
	for rel := range examined {
		result.Examined = append(result.Examined, rel)
	}
	sort.Strings(result.Examined)

	for _, key := range order {
		result.Findings = append(result.Findings, findings[key])
	}

	// The anchor. If anything in the tree borrows from an enclave, the key
	// file's fill window must be there and must borrow exactly once.
	if anchor.borrowsSeen > 0 {
		switch {
		case anchor.declLine == 0:
			return Result{}, evidence, fmt.Errorf("custody: the tree borrows from enclaves but %s.%s — the borrow window the scanner is anchored on — does not exist; "+
				"the model has moved and the scanner must be re-anchored rather than left passing vacuously", anchorWindow.Dir, anchorWindow.Func)
		case anchor.count != 1:
			result.Findings = append(result.Findings, Finding{
				File: anchor.declFile, Line: anchor.declLine,
				Message: fmt.Sprintf("%s calls %s.%s %d time(s); it is the anchor window and must call it exactly once, so that the passphrase's bytes enter the model in one place the reader can find. "+
					"If the window has moved, move the anchor in internal/guards/custody.go with it.",
					anchorWindow.Func, enclaveType, borrowMethod, anchor.count),
			})
		}
	}
	sortFindings(result.Findings)
	return result, evidence, nil
}

// custodyLoader is the one source importer every scan in a process shares; the lock guards it.
var custodyLoader struct {
	sync.Mutex
	fset *token.FileSet
	imp  types.Importer
}

// custodyAnchor records what the scan saw of the anchor window.
type custodyAnchor struct {
	// borrowsSeen counts every WithBytes site in the tree, window or not,
	// deduplicated across configurations.
	borrowsSeen int
	seen        map[string]struct{}

	// declFile and declLine locate the anchor function, when it exists.
	declFile string
	declLine int

	// count is how many WithBytes sites the anchor contains.
	count int
}

// custodyModulePath reads the module path from the go.mod at or above root, or returns a placeholder.
func custodyModulePath(root string) string {
	moduleRoot, err := Root(root)
	if err != nil {
		return "scanned"
	}
	// #nosec G304 -- moduleRoot was located by walking up from the scan root.
	content, err := os.ReadFile(filepathJoin(moduleRoot, "go.mod"))
	if err != nil {
		return "scanned"
	}
	for _, line := range strings.Split(string(content), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return "scanned"
}

// sortFindings orders findings by file then line, so the report reads in
// source order whatever order the configurations produced them in.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
}

// custodyPackage scans one type-checked package under one configuration.
type custodyPackage struct {
	root     string
	dir      string
	fset     *token.FileSet
	info     *types.Info
	anchor   *custodyAnchor
	evidence *custodyEvidence
}

// file reports every custody finding in one file.
func (p custodyPackage) file(file *ast.File) []Finding {
	var findings []Finding
	rel := p.rel(file.Pos())

	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			findings = append(findings, p.funcDecl(rel, decl)...)
		case *ast.GenDecl:
			findings = append(findings, p.genDecl(rel, decl)...)
		}
	}
	return findings
}

// rel returns a position's file, relative to the tree root.
func (p custodyPackage) rel(pos token.Pos) string {
	name := p.fset.Position(pos).Filename
	prefix := filepathJoin(p.root, "")
	return strings.TrimPrefix(strings.ReplaceAll(name, string(os.PathSeparator), "/"), strings.ReplaceAll(prefix, string(os.PathSeparator), "/"))
}

// line returns a position's 1-based line.
func (p custodyPackage) line(pos token.Pos) int {
	return p.fset.Position(pos).Line
}

// funcDecl applies rules 1–4 to one top-level function.
func (p custodyPackage) funcDecl(rel string, decl *ast.FuncDecl) []Finding {
	var findings []Finding
	name := funcDeclName(decl)

	// The anchor's whereabouts, for the count at the end of the scan.
	if p.dir == anchorWindow.Dir && name == anchorWindow.Func {
		p.anchor.declFile = rel
		p.anchor.declLine = p.line(decl.Pos())
	}

	// Rule 5 on the declaration's own signature.
	if decl.Name.IsExported() {
		findings = append(findings, p.clearTextSeam(rel, decl.Type, "func "+name)...)
	}

	if decl.Body == nil {
		return findings
	}

	// Rules 1 and 2 on every selection in the body, and rule 1's bookkeeping.
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		selection, ok := p.info.Selections[sel]
		if !ok || selection.Kind() == types.FieldVal {
			return true
		}
		fn, ok := selection.Obj().(*types.Func)
		if !ok {
			return true
		}
		recv := receiverNamed(fn)
		if recv == nil {
			return true
		}
		findings = append(findings, p.methodUse(rel, sel, fn, recv, name)...)
		return true
	})

	// Rule 4 on the declaration and every closure inside it.
	findings = append(findings, p.borrowedKeys(rel, decl.Type, decl.Body)...)
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		if lit, ok := node.(*ast.FuncLit); ok {
			findings = append(findings, p.borrowedKeys(rel, lit.Type, lit.Body)...)
		}
		return true
	})
	return findings
}

// methodUse applies rules 1 and 2 to one method selection, called or not.
func (p custodyPackage) methodUse(rel string, sel *ast.SelectorExpr, fn *types.Func, recv *types.Named, enclosing string) []Finding {
	recvPkg := ""
	if recv.Obj().Pkg() != nil {
		recvPkg = recv.Obj().Pkg().Path()
	}
	method := fn.Name()
	line := p.line(sel.Sel.Pos())

	switch {
	case recvPkg == enclavePackage && recv.Obj().Name() == enclaveType:
		if method != borrowMethod {
			return nil
		}
		return p.borrow(rel, sel, enclosing)

	case strings.HasSuffix(recvPkg, "/"+luksDir) && recv.Obj().Name() == backendType:
		if _, keyTaking := keyTakingMethods[method]; !keyTaking || p.dir == luksDir {
			return nil
		}
		return []Finding{{
			File: rel, Line: line,
			Message: fmt.Sprintf("this calls luks.%s.%s, which takes the passphrase enclave, from outside %s. Only the code that owns the enclave's lifetime may hand it over: "+
				"call the corresponding luks.Manager method instead, and let it take a fresh enclave from the KeyProvider and destroy it for you.",
				backendType, method, luksDir),
		}}
	}
	return nil
}

// borrow records one WithBytes site and reports it if it is outside every
// named window.
func (p custodyPackage) borrow(rel string, sel *ast.SelectorExpr, enclosing string) []Finding {
	site := fmt.Sprintf("%s:%d:%d", rel, p.line(sel.Sel.Pos()), p.fset.Position(sel.Sel.Pos()).Column)
	if p.anchor.seen == nil {
		p.anchor.seen = map[string]struct{}{}
	}
	if _, dup := p.anchor.seen[site]; dup {
		return nil
	}
	p.anchor.seen[site] = struct{}{}
	p.anchor.borrowsSeen++

	for _, window := range borrowWindows {
		if window.Dir != p.dir || window.Func != enclosing {
			continue
		}
		p.evidence.windowsSeen[window.Dir+":"+window.Func]++
		if window == anchorWindow {
			p.anchor.count++
		}
		return nil
	}

	var allowed []string
	for _, window := range borrowWindows {
		allowed = append(allowed, window.Dir+"."+window.Func)
	}
	return []Finding{{
		File: rel, Line: p.line(sel.Sel.Pos()),
		Message: fmt.Sprintf("%s.%s is called from %s.%s, which is not a borrow window. Key material becomes bytes only inside the functions named in internal/guards/custody.go (%s); "+
			"route the operation through luks.Manager, which borrows for you — or, if this really is a new place the model must expose bytes, add it to borrowWindows with its reason.",
			enclaveType, borrowMethod, p.dir, enclosing, strings.Join(allowed, ", ")),
	}}
}

// genDecl applies rule 4 to exported interface methods and func types.
func (p custodyPackage) genDecl(rel string, decl *ast.GenDecl) []Finding {
	var findings []Finding
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || !typeSpec.Name.IsExported() {
			continue
		}
		switch t := typeSpec.Type.(type) {
		case *ast.InterfaceType:
			for _, method := range t.Methods.List {
				fnType, ok := method.Type.(*ast.FuncType)
				if !ok || len(method.Names) == 0 || !method.Names[0].IsExported() {
					continue
				}
				findings = append(findings, p.clearTextSeam(rel, fnType, typeSpec.Name.Name+"."+method.Names[0].Name)...)
			}
		case *ast.FuncType:
			findings = append(findings, p.clearTextSeam(rel, t, "type "+typeSpec.Name.Name)...)
		}
	}
	return findings
}

// clearTextSeam applies rule 4 to one signature.
func (p custodyPackage) clearTextSeam(rel string, sig *ast.FuncType, what string) []Finding {
	var findings []Finding
	report := func(field *ast.Field, name *ast.Ident, role string) {
		findings = append(findings, Finding{
			File: rel, Line: p.line(name.Pos()),
			Message: fmt.Sprintf("%s is exported and its %s %q is a %s: key material would cross a package boundary in the clear, on the ordinary heap, where it cannot be wiped. "+
				"Carry it as a *enclave.MemoryEnclave — the caller unseals into one and the callee borrows — or, if this names a path or an identifier rather than the material, "+
				"call it that (keyPath, tokenID).",
				what, role, name.Name, types.ExprString(field.Type)),
		})
	}
	for _, field := range sig.Params.List {
		if !p.isClearText(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if isMaterialName(name.Name, p.isString(field.Type)) {
				report(field, name, "parameter")
			}
		}
	}
	if sig.Results == nil {
		return findings
	}
	for _, field := range sig.Results.List {
		if !p.isClearText(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if isMaterialName(name.Name, p.isString(field.Type)) {
				report(field, name, "result")
			}
		}
	}
	return findings
}

// isString reports whether a type expression's underlying type is string. It
// is only consulted for expressions isClearText already accepted.
func (p custodyPackage) isString(expr ast.Expr) bool {
	tv, ok := p.info.Types[expr]
	if !ok || tv.Type == nil {
		return false
	}
	_, isSlice := tv.Type.Underlying().(*types.Slice)
	return !isSlice
}

// isClearText reports whether a type expression's underlying type is string
// or []byte — the two shapes unprotected material takes, named types over
// them included.
func (p custodyPackage) isClearText(expr ast.Expr) bool {
	tv, ok := p.info.Types[expr]
	if !ok || tv.Type == nil {
		return false
	}
	return isClearTextType(tv.Type)
}

// isClearTextType is isClearText on a resolved type.
func isClearTextType(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String || u.Kind() == types.UntypedString
	case *types.Slice:
		elem, ok := u.Elem().Underlying().(*types.Basic)
		return ok && (elem.Kind() == types.Byte || elem.Kind() == types.Uint8)
	}
	return false
}

// isMaterialName reports whether an identifier names key material; a bare string key is a lookup key.
func isMaterialName(name string, isString bool) bool {
	words := splitWords(name)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	if last == "key" && len(words) == 1 && isString {
		return false
	}
	if _, material := materialWords[last]; material {
		return true
	}
	if _, carrier := materialCarriers[last]; carrier && len(words) >= 2 {
		_, material := materialWords[words[len(words)-2]]
		return material
	}
	return false
}

// splitWords breaks an identifier at case and underscore boundaries and
// lowercases the parts: luksKeyFile → luks key file, ROOT_PASSWORD → root
// password, tokenID → token id.
func splitWords(name string) []string {
	var (
		words []string
		word  []rune
	)
	flush := func() {
		if len(word) > 0 {
			words = append(words, strings.ToLower(string(word)))
			word = word[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_':
			flush()
		case unicode.IsUpper(r):
			// A boundary before an upper-case rune, except inside a run of
			// them (ID, LUKS) — the run ends where a lower-case rune follows.
			if i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]) ||
				(unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
				flush()
			}
			word = append(word, r)
		default:
			word = append(word, r)
		}
	}
	flush()
	return words
}

// borrowedKeys applies rule 3 to one function or closure: each []byte
// parameter named key or passphrase may appear only as a direct call argument.
func (p custodyPackage) borrowedKeys(rel string, sig *ast.FuncType, body *ast.BlockStmt) []Finding {
	if body == nil {
		return nil
	}
	borrowed := map[types.Object]struct{}{}
	for _, field := range sig.Params.List {
		if !p.isClearText(field.Type) {
			continue
		}
		if _, isSlice := p.info.Types[field.Type].Type.Underlying().(*types.Slice); !isSlice {
			continue
		}
		for _, name := range field.Names {
			if _, watched := borrowedKeyNames[name.Name]; !watched {
				continue
			}
			if obj := p.info.Defs[name]; obj != nil {
				borrowed[obj] = struct{}{}
			}
		}
	}
	if len(borrowed) == 0 {
		return nil
	}

	var (
		findings []Finding
		stack    []ast.Node
	)
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, node)

		ident, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		obj := p.info.Uses[ident]
		if obj == nil {
			return true
		}
		if _, isKey := borrowed[obj]; !isKey {
			return true
		}
		if why := p.retains(stack); why != "" {
			findings = append(findings, Finding{
				File: rel, Line: p.line(ident.Pos()),
				Message: fmt.Sprintf("%q is a []byte borrowed from locked memory for the length of this call, and here it %s. "+
					"A borrowed key may appear only as a direct argument of a call (len(key) included), or in a composite literal that is itself the call's argument; "+
					"anything else is a copy or a reference the enclave cannot take back.", ident.Name, why),
			})
		}
		return true
	})
	return findings
}

// retains decides whether the identifier at the top of stack is in a position
// rule 3 refuses, and says which. The stack runs from the function body down
// to the identifier itself.
func (p custodyPackage) retains(stack []ast.Node) string {
	ident := stack[len(stack)-1]

	// A closure between the use and the declaring function keeps the key alive
	// for as long as the closure does — unless the closure is invoked on the
	// spot, which is a scope and not a retention.
	for i := len(stack) - 2; i >= 0; i-- {
		lit, ok := stack[i].(*ast.FuncLit)
		if !ok {
			continue
		}
		if call, ok := stack[i-1].(*ast.CallExpr); ok && call.Fun == lit {
			continue
		}
		return "is captured by a closure that may outlive the call"
	}

	if len(stack) < 2 {
		return "is used outside any call"
	}
	parent := stack[len(stack)-2]

	switch parent := parent.(type) {
	case *ast.CallExpr:
		if parent.Fun == ident {
			return "is used outside any call"
		}
		return p.calleeCopies(parent)

	case *ast.KeyValueExpr:
		if parent.Value != ident || len(stack) < 4 {
			return "is used outside any call"
		}
		return p.literalRetains(stack[len(stack)-3], stack[len(stack)-4])

	case *ast.CompositeLit:
		if len(stack) < 3 {
			return "is used outside any call"
		}
		return p.literalRetains(parent, stack[len(stack)-3])
	}
	return "is used outside any call"
}

// literalRetains applies the composite-literal refinement: the literal is fine
// only when it is itself a direct argument of a call.
func (p custodyPackage) literalRetains(lit ast.Node, above ast.Node) string {
	call, ok := above.(*ast.CallExpr)
	if !ok {
		return "is stored in a composite literal that is not passed straight to a call"
	}
	for _, arg := range call.Args {
		if arg == lit {
			return p.calleeCopies(call)
		}
	}
	return "is stored in a composite literal that is not passed straight to a call"
}

// calleeCopies refuses the calls that are copies wearing a call's shape: the
// append and copy builtins, and a type conversion.
func (p custodyPackage) calleeCopies(call *ast.CallExpr) string {
	if tv, ok := p.info.Types[call.Fun]; ok && tv.IsType() {
		return "is converted with " + types.ExprString(call.Fun) + "(...), which copies it onto the heap"
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if builtin, ok := p.info.Uses[ident].(*types.Builtin); ok {
			switch builtin.Name() {
			case "append", "copy":
				return "is copied by " + builtin.Name()
			}
		}
	}
	return ""
}

// receiverNamed returns the named type a method is declared on, through a
// pointer if there is one, or nil for a function.
func receiverNamed(fn *types.Func) *types.Named {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named
	}
	return nil
}

// funcDeclName renders a declaration the way go doc does: F, T.M or (*T).M.
func funcDeclName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return decl.Name.Name
	}
	recv := decl.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		return "(*" + baseTypeName(star.X) + ")." + decl.Name.Name
	}
	return baseTypeName(recv) + "." + decl.Name.Name
}

// baseTypeName strips type parameters from a receiver type expression.
func baseTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return baseTypeName(e.X)
	case *ast.IndexListExpr:
		return baseTypeName(e.X)
	}
	return types.ExprString(expr)
}
