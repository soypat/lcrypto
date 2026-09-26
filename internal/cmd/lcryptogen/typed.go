package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Type-directed rules. Syntactic rules cannot tell x.Bytes() on one type from
// another; these resolve every call with go/types, so the generated packages are
// type checked in order, each against the ones before it.

// variantKind tells how a generated allocation-free variant is called.
type variantKind int

const (
	// kindOutlined: `func (r *T) M() R { var out [N]E; return r.m(&out) }`, the std
	// idiom that lets gc inline the array into the caller. TinyGo does not, and
	// heap allocates out. Variant MTo(out *[N]E) R writes into caller memory.
	kindOutlined variantKind = iota
	// kindCtor: a function returning a fresh *T, `v := &T{..}; ...; return v` or
	// `return &T{..}`. Variant MInto(v *T, args...) *T initializes caller memory.
	kindCtor
)

// variant is a generated allocation-free counterpart of an upstream function.
type variant struct {
	kind    variantKind
	name    string     // Generated function or method name.
	storage types.Type // Type of the caller provided memory: [N]E or T.
}

// typedState is shared across packages: each package is type checked against
// those generated before it.
type typedState struct {
	root     string
	fset     *token.FileSet
	pkgs     map[string]*types.Package // By import path.
	variants map[string]variant        // By types.Func.FullName of the upstream function.
	std      types.Importer
}

func newTypedState(root string) *typedState {
	fset := token.NewFileSet()
	return &typedState{
		root:     root,
		fset:     fset,
		pkgs:     map[string]*types.Package{},
		variants: map[string]variant{},
		std:      importer.ForCompiler(fset, "source", nil),
	}
}

func (ts *typedState) Import(path string) (*types.Package, error) {
	if p, ok := ts.pkgs[path]; ok {
		return p, nil
	}
	if rel, ok := strings.CutPrefix(path, modulePath+"/"); ok {
		// Hand-written packages, i.e. internal/std/cpu, are checked from disk.
		overlays, err := readOverlays(ts.root, rel)
		if err != nil || len(overlays) == 0 {
			return nil, fmt.Errorf("package %s not generated yet: order packages by dependency", path)
		}
		pkg, _, _, err := ts.check(path, nil, overlays)
		if err != nil {
			return nil, err
		}
		ts.pkgs[path] = pkg
		return pkg, nil
	}
	return ts.std.Import(path)
}

// check type checks the non-test files of a package. overlays are the hand-written files.
func (ts *typedState) check(path string, jobs []*fileJob, overlays map[string][]byte) (*types.Package, *types.Info, map[*fileJob]*ast.File, error) {
	var files []*ast.File
	byJob := map[*fileJob]*ast.File{}
	for _, job := range jobs {
		if job.isTest {
			continue
		}
		f, err := parser.ParseFile(ts.fset, job.name, job.src, parser.ParseComments)
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, f)
		byJob[job] = f
	}
	names := make([]string, 0, len(overlays))
	for name := range overlays {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := parser.ParseFile(ts.fset, name, overlays[name], parser.ParseComments)
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: ts, FakeImportC: false}
	pkg, err := conf.Check(path, ts.fset, files, info)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("type check: %w", err)
	}
	return pkg, info, byJob, nil
}

// readOverlays returns the hand-written non-test .go files of a generated package.
func readOverlays(root, dst string) (map[string][]byte, error) {
	dir := filepath.Join(root, dst)
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if ok, err := build.Default.MatchFile(dir, name); err != nil || !ok {
			continue // Build constraints of hand-written files hold for the host.
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(b, []byte(headerPrefix)) {
			out[name] = b
		}
	}
	return out, nil
}

// typedRules generates allocation-free variants of the package's outlined and
// constructor functions, then rewrites calls to every known variant.
func (ts *typedState) typedRules(root string, ps *pkgState, jobs []*fileJob) ([]*fileJob, error) {
	path := modulePath + "/" + stdDir + "/" + ps.spec.Dst
	overlays, err := readOverlays(root, stdDir+"/"+ps.spec.Dst)
	if err != nil {
		return nil, err
	}
	// Variants are found syntactically so the generated file can join the first type check.
	// Constructors built on other constructors are found by iterating to a fixpoint.
	var decls []string
	ctors := map[string]bool{} // Same-package functions (not methods) with a ctor variant.
	done := map[*ast.FuncDecl]bool{}
	type parsed struct {
		job *fileJob
		f   *ast.File
	}
	var pfiles []parsed
	for _, job := range jobs {
		if job.isTest {
			continue
		}
		f, err := parseFile(job)
		if err != nil {
			return nil, err
		}
		pfiles = append(pfiles, parsed{job, f})
	}
	for changed := true; changed; {
		changed = false
		for _, pf := range pfiles {
			for _, d := range pf.f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || done[fd] {
					continue
				}
				if src := variantDecl(pf.job.src, pf.f, fd, ctors); src != "" {
					decls = append(decls, src)
					done[fd] = true
					changed = true
					if fd.Recv == nil && strings.Contains(src, "Into(") {
						ctors[fd.Name.Name] = true
					}
				}
			}
		}
	}
	if len(decls) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "package %s\n\n", ps.pkgName)
		for _, d := range decls {
			b.WriteString(d)
			b.WriteString("\n\n")
		}
		job := &fileJob{spec: ps.spec, name: "variants_gen.go", src: []byte(b.String()), origin: ps.spec.Src, variants: true}
		if err := ps.fixImports(job); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	pkg, info, files, err := ts.check(path, jobs, overlays)
	if err != nil {
		return nil, err
	}
	ts.register(pkg, info, files)
	for _, job := range jobs {
		f, ok := files[job]
		if !ok || job.variants {
			continue
		}
		edits := ts.rewriteCalls(job, f, pkg, info)
		if len(edits) == 0 {
			continue
		}
		if job.src, err = applyEdits(job.src, edits); err != nil {
			return nil, fmt.Errorf("%s: %w", job.name, err)
		}
		if err := ps.fixImports(job); err != nil {
			return nil, err
		}
	}
	return jobs, nil
}

// finalCheck type checks the finished package, which later packages import.
func (ts *typedState) finalCheck(root string, ps *pkgState, jobs []*fileJob) error {
	path := modulePath + "/" + stdDir + "/" + ps.spec.Dst
	overlays, err := readOverlays(root, stdDir+"/"+ps.spec.Dst)
	if err != nil {
		return err
	}
	pkg, _, _, err := ts.check(path, jobs, overlays)
	if err != nil {
		return err
	}
	ts.pkgs[path] = pkg
	return nil
}

// variantDecl returns the source of the allocation-free variant of fd, or "".
// ctors names same-package functions known to have a constructor variant: a
// function starting with `v := ctor(args)` is a constructor too.
func variantDecl(src []byte, f *ast.File, fd *ast.FuncDecl, ctors map[string]bool) string {
	if fd.Body == nil || fd.Type.TypeParams != nil {
		return ""
	}
	text := func(n ast.Node) string { return string(src[n.Pos()-f.FileStart : n.End()-f.FileStart]) }
	recv := ""
	if fd.Recv != nil {
		recv = text(fd.Recv) + " "
	}
	params := text(fd.Type.Params)
	params = params[1 : len(params)-1] // Without parentheses.
	results := ""
	if fd.Type.Results != nil {
		results = " " + text(fd.Type.Results)
	}
	name := fd.Name.Name
	body := fd.Body.List

	// Outlined array: var out [N]E; return call(..., &out, ...).
	if fd.Type.Params.NumFields() == 0 && len(body) == 2 {
		if arr, ok := outlinedArray(body[0]); ok {
			if ret, ok := body[1].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				if call, ok := ret.Results[0].(*ast.CallExpr); ok && countAddrOf(call, arr.name) == 1 {
					r := text(ret.Results[0])
					r = strings.Replace(r, "&"+arr.name, "out", 1)
					return fmt.Sprintf("// %s is the allocation-free [%s]: it writes into out, which the\n// result aliases, instead of a new array.\nfunc %s%s(out *%s)%s {\n\treturn %s\n}",
						variantName(name, "To"), docName(fd), recv, variantName(name, "To"), text(arr.typ), results, r)
				}
			}
		}
	}

	// Constructor: result *T with T declared in this file's package.
	if fd.Type.Results == nil || len(fd.Type.Results.List) != 1 || len(fd.Type.Results.List[0].Names) > 1 {
		return ""
	}
	star, ok := fd.Type.Results.List[0].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	tname, ok := star.X.(*ast.Ident)
	if !ok || len(body) == 0 {
		return ""
	}
	var v string
	var init string
	switch first := body[0].(type) {
	case *ast.ReturnStmt:
		// return &T{...}
		if len(body) != 1 || len(first.Results) != 1 {
			return ""
		}
		v = "into"
		if lit, ok := addrOfLit(first.Results[0], tname.Name); ok {
			init = zeroThenAssign(text, v, tname.Name, lit) + "\n\treturn " + v
		} else if chain, ok := newChain(first.Results[0], text); ok && chain != "" && isNew(chainRoot(first.Results[0]), tname.Name) {
			// return new(T).M(...): methods of T returning *T.
			init = fmt.Sprintf("*%s = %s{}\n\treturn %s%s", v, tname.Name, v, chain)
		} else {
			return ""
		}
	case *ast.AssignStmt:
		// v := &T{...} or v := new(T); ...; return v
		if first.Tok != token.DEFINE || len(first.Lhs) != 1 || len(first.Rhs) != 1 {
			return ""
		}
		id, ok := first.Lhs[0].(*ast.Ident)
		if !ok {
			return ""
		}
		v = id.Name
		if lit, ok := addrOfLit(first.Rhs[0], tname.Name); ok {
			init = zeroThenAssign(text, v, tname.Name, lit)
		} else if isNew(first.Rhs[0], tname.Name) {
			init = fmt.Sprintf("*%s = %s{}", v, tname.Name)
		} else if call, ok := first.Rhs[0].(*ast.CallExpr); ok && isCtorCall(call, ctors) {
			args := v
			for _, a := range call.Args {
				args += ", " + text(a)
			}
			init = fmt.Sprintf("%sInto(%s)", call.Fun.(*ast.Ident).Name, args)
		} else {
			return ""
		}
		if !onlyReturns(fd.Body, v) {
			return ""
		}
		var rest []string
		for _, s := range body[1:] {
			rest = append(rest, text(s))
		}
		init += "\n\t" + strings.Join(rest, "\n\t")
	default:
		return ""
	}
	if paramNamed(fd, v) {
		return ""
	}
	sep := ""
	if params != "" {
		sep = ", "
	}
	return fmt.Sprintf("// %s is the allocation-free [%s]: it initializes %s instead of a new %s.\nfunc %s%s(%s *%s%s%s)%s {\n\t%s\n}",
		variantName(name, "Into"), docName(fd), v, tname.Name, recv, variantName(name, "Into"), v, tname.Name, sep, params, results, init)
}

type arrayDecl struct {
	name string
	typ  *ast.ArrayType
}

func outlinedArray(s ast.Stmt) (arrayDecl, bool) {
	ds, ok := s.(*ast.DeclStmt)
	if !ok {
		return arrayDecl{}, false
	}
	gd := ds.Decl.(*ast.GenDecl)
	if gd.Tok != token.VAR || len(gd.Specs) != 1 {
		return arrayDecl{}, false
	}
	vs := gd.Specs[0].(*ast.ValueSpec)
	at, ok := vs.Type.(*ast.ArrayType)
	if !ok || at.Len == nil || len(vs.Names) != 1 || vs.Values != nil {
		return arrayDecl{}, false
	}
	return arrayDecl{vs.Names[0].Name, at}, true
}

func countAddrOf(n ast.Node, name string) int {
	count, uses := 0, 0
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.UnaryExpr:
			if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND && id.Name == name {
				count++
			}
		case *ast.Ident:
			if n.Name == name {
				uses++
			}
		}
		return true
	})
	if uses != count {
		return -1 // Also used other than by address.
	}
	return count
}

func addrOfLit(e ast.Expr, typ string) (*ast.CompositeLit, bool) {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return nil, false
	}
	lit, ok := u.X.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	id, ok := lit.Type.(*ast.Ident)
	return lit, ok && id.Name == typ
}

func isNew(e ast.Expr, typ string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	fn, ok := call.Fun.(*ast.Ident)
	arg, ok2 := call.Args[0].(*ast.Ident)
	return ok && ok2 && fn.Name == "new" && arg.Name == typ
}

// zeroThenAssign initializes *v from a keyed literal one field at a time: TinyGo
// builds a non-zero composite literal of a large struct in a heap temporary.
func zeroThenAssign(text func(ast.Node) string, v, typ string, lit *ast.CompositeLit) string {
	lines := []string{fmt.Sprintf("*%s = %s{}", v, typ)}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return fmt.Sprintf("*%s = %s", v, text(lit)) // Unkeyed: keep the literal.
		}
		lines = append(lines, fmt.Sprintf("%s.%s = %s", v, text(kv.Key), text(kv.Value)))
	}
	return strings.Join(lines, "\n\t")
}

// onlyReturns reports whether every return in body returns exactly v, and there is one at the end.
func onlyReturns(body *ast.BlockStmt, v string) bool {
	ok := true
	ast.Inspect(body, func(n ast.Node) bool {
		if _, lit := n.(*ast.FuncLit); lit {
			return false
		}
		if r, isRet := n.(*ast.ReturnStmt); isRet {
			if len(r.Results) != 1 {
				ok = false
			} else if id, isID := r.Results[0].(*ast.Ident); !isID || id.Name != v {
				ok = false
			}
		}
		return true
	})
	last, isRet := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok && isRet && last != nil
}

func paramNamed(fd *ast.FuncDecl, v string) bool {
	for _, fl := range [...]*ast.FieldList{fd.Recv, fd.Type.Params} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if n.Name == v {
					return true
				}
			}
		}
	}
	return false
}

func variantName(name, suffix string) string { return name + suffix }

func docName(fd *ast.FuncDecl) string {
	if fn := funcName(fd); strings.Contains(fn, ".") {
		return fn
	}
	return fd.Name.Name
}

// register records the variants of pkg found in its generated variants file.
func (ts *typedState) register(pkg *types.Package, info *types.Info, files map[*fileJob]*ast.File) {
	for job, f := range files {
		if !job.variants {
			continue
		}
		for _, d := range f.Decls {
			fd := d.(*ast.FuncDecl)
			obj := info.Defs[fd.Name].(*types.Func)
			sig := obj.Signature()
			var kind variantKind
			var orig string
			switch {
			case strings.HasSuffix(fd.Name.Name, "Into"):
				kind, orig = kindCtor, strings.TrimSuffix(fd.Name.Name, "Into")
			default:
				kind, orig = kindOutlined, strings.TrimSuffix(fd.Name.Name, "To")
			}
			storage := sig.Params().At(0).Type().(*types.Pointer).Elem()
			key := strings.TrimSuffix(obj.FullName(), fd.Name.Name) + orig
			ts.variants[key] = variant{kind: kind, name: fd.Name.Name, storage: storage}
		}
	}
}

// rewriteCalls redirects calls to functions with variants: `x.M(args)` becomes
// `x.MTo(&mArr, args)` or `x.MInto(&mObj, args)`, the storage declared right
// before the enclosing statement. Calls in loop, if and switch headers are left alone.
func (ts *typedState) rewriteCalls(job *fileJob, f *ast.File, pkg *types.Package, info *types.Info) []edit {
	off := func(p token.Pos) int { return int(p - f.FileStart) }
	text := func(n ast.Node) string { return string(job.src[off(n.Pos()):off(n.End())]) }
	qual := func(p *types.Package) string {
		if p == pkg {
			return ""
		}
		return p.Name()
	}
	var edits []edit
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		used := map[string]bool{}
		ast.Inspect(fd, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				used[id.Name] = true
			}
			return true
		})
		forEachStmtNode(fd.Body, func(n ast.Node, stmt ast.Stmt) {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return
			}
			var fn *types.Func
			var nameID *ast.Ident
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				fn, _ = info.Uses[fun].(*types.Func)
				nameID = fun
			case *ast.SelectorExpr:
				if sel, ok := info.Selections[fun]; ok {
					fn, _ = sel.Obj().(*types.Func)
				} else {
					fn, _ = info.Uses[fun.Sel].(*types.Func)
				}
				nameID = fun.Sel
			}
			if fn == nil {
				return
			}
			v, ok := ts.variants[fn.FullName()]
			if !ok || fn.Name() == "" {
				return
			}
			if fn.Pkg() != pkg && !isExported(v.name) {
				return
			}
			storage := types.TypeString(v.storage, qual)
			if strings.Contains(storage, ".") && !exportedTypeString(v.storage) {
				return // Unnameable here.
			}
			suffix := "Obj"
			if v.kind == kindOutlined {
				suffix = "Arr"
			}
			base := storageName(call, stmt, fn.Name()) + suffix
			name := base
			for i := 2; used[name]; i++ {
				name = base + strconv.Itoa(i)
			}
			used[name] = true
			at := off(stmt.Pos())
			arg := "&" + name
			if len(call.Args) > 0 {
				arg += ", "
			}
			edits = append(edits,
				edit{start: at, end: at, text: fmt.Sprintf("var %s %s\n", name, storage)},
				edit{start: off(nameID.Pos()), end: off(nameID.End()), text: v.name},
				edit{start: off(call.Lparen) + 1, end: off(call.Lparen) + 1, text: arg},
			)
			_ = text
		})
	}
	return edits
}

func isExported(name string) bool { return name != "" && unicode.IsUpper(rune(name[0])) }

// exportedTypeString reports whether every named type in t is exported.
func exportedTypeString(t types.Type) bool {
	switch t := t.(type) {
	case *types.Named:
		return t.Obj().Exported() || t.Obj().Pkg() == nil
	case *types.Array:
		return exportedTypeString(t.Elem())
	}
	return true
}

// storageName names caller storage after the variable the call's result is assigned to,
// else after the called function.
func storageName(call *ast.CallExpr, stmt ast.Stmt, fn string) string {
	if as, ok := stmt.(*ast.AssignStmt); ok && as.Tok == token.DEFINE {
		for i, r := range as.Rhs {
			if chainRoot(r) == call && len(as.Lhs) == len(as.Rhs) {
				if id, ok := as.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
					return id.Name
				}
			}
		}
	}
	return strings.ToLower(fn[:1]) + fn[1:]
}

// forEachStmtNode calls fn for every node inside a statement that sits in a block,
// with that statement. Headers evaluated once, if and switch headers, for loop
// init and range operands, belong to their statement; loop conditions and posts,
// evaluated repeatedly, and function literals are skipped.
func forEachStmtNode(body *ast.BlockStmt, fn func(n ast.Node, stmt ast.Stmt)) {
	var visitList func(list []ast.Stmt)
	var visit func(n ast.Node, stmt ast.Stmt)
	visitList = func(list []ast.Stmt) {
		for _, s := range list {
			visit(s, s)
		}
	}
	opt := func(n ast.Node, stmt ast.Stmt) {
		if n != nil && !reflect.ValueOf(n).IsNil() {
			visit(n, stmt)
		}
	}
	visit = func(n ast.Node, stmt ast.Stmt) {
		switch n := n.(type) {
		case *ast.BlockStmt:
			visitList(n.List)
			return
		case *ast.CaseClause:
			visitList(n.Body)
			return
		case *ast.CommClause:
			visitList(n.Body)
			return
		case *ast.ForStmt:
			opt(n.Init, stmt)
			visit(n.Body, nil)
			return
		case *ast.RangeStmt:
			visit(n.X, stmt)
			visit(n.Body, nil)
			return
		case *ast.IfStmt:
			opt(n.Init, stmt)
			visit(n.Cond, stmt)
			visit(n.Body, nil)
			if n.Else != nil {
				visit(n.Else, stmt) // An else-if header runs at most once per stmt.
			}
			return
		case *ast.SwitchStmt:
			opt(n.Init, stmt)
			opt(n.Tag, stmt)
			visit(n.Body, nil)
			return
		case *ast.TypeSwitchStmt:
			opt(n.Init, stmt)
			visit(n.Assign, stmt)
			visit(n.Body, nil)
			return
		case *ast.SelectStmt:
			visit(n.Body, nil)
			return
		case *ast.FuncLit:
			return
		}
		if stmt != nil {
			fn(n, stmt)
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n || c == nil {
				return c != nil
			}
			visit(c, stmt)
			return false
		})
	}
	visit(body, nil)
}

// chainRoot returns the call a method chain like f().a().b() starts with, or e.
func chainRoot(e ast.Expr) ast.Expr {
	for {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return e
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return e
		}
		inner, ok := sel.X.(*ast.CallExpr)
		if !ok {
			return e
		}
		e = inner
	}
}

// isCtorCall reports whether call calls a same-package constructor by name.
func isCtorCall(call *ast.CallExpr, ctors map[string]bool) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && ctors[id.Name]
}
