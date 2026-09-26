package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// edit replaces src[start:end] with text.
type edit struct {
	start, end int
	text       string
}

func applyEdits(src []byte, edits []edit) ([]byte, error) {
	// Insertions sort before replacements starting at the same offset.
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end < edits[j].end
	})
	var out bytes.Buffer
	last := 0
	for _, e := range edits {
		if e.start < last {
			return nil, fmt.Errorf("overlapping edits at offset %d", e.start)
		}
		out.Write(src[last:e.start])
		out.WriteString(e.text)
		last = e.end
	}
	out.Write(src[last:])
	return out.Bytes(), nil
}

// keepFile reports whether a file's build constraint holds for a pure Go build:
// purego set, go1.N release tags up to the pinned version set, every other tag unset.
func keepFile(src []byte) (bool, error) { return matchBuild(src, buildTag) }

// matchBuild evaluates the //go:build line of src, if any, with tag.
func matchBuild(src []byte, tag func(string) bool) (bool, error) {
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return false, err
		}
		return expr.Eval(tag), nil
	}
	return true, nil
}

// kitBuildTag fixes the platform Kit packages are type checked for, whatever the host.
func kitBuildTag(tag string) bool {
	switch tag {
	case "linux", "unix", "amd64", "gc":
		return true
	}
	return buildTag(tag) && tag != "purego"
}

func buildTag(tag string) bool {
	if tag == "purego" {
		return true
	}
	if minor, ok := strings.CutPrefix(tag, "go1."); ok {
		n, err := strconv.Atoi(minor)
		return err == nil && n <= pinnedMinor()
	}
	return false
}

func pinnedMinor() int {
	s := strings.TrimPrefix(goVersion, "go1.")
	s, _, _ = strings.Cut(s, ".")
	n, _ := strconv.Atoi(s)
	return n
}

// fileJob is one source file being ported.
type fileJob struct {
	spec   *pkgSpec
	name   string // Base name.
	src    []byte // Current contents, rewritten stage by stage.
	origin string // Upstream path for the header.
	isTest bool
	// hoisted marks the synthesized file of hoisted errors.
	hoisted bool
	// variants marks the synthesized file of allocation-free variants.
	variants bool
	// fields marks the synthesized file of field array accessors.
	fields bool
	// decls marks the synthesized file of declarations from the spec.
	decls bool
}

// pkgState carries package-wide bookkeeping across files.
type pkgState struct {
	spec       *pkgSpec
	pkgName    string
	consts     map[string]bool   // Package-level constant names, for constant make lengths.
	topNames   map[string]bool   // All package-level names, to avoid collisions.
	dropHits   map[string]int    // DropDecls matches.
	errVars    map[string]string // errors.New message -> hoisted var name.
	errOrder   []string          // Messages in first-seen order.
	patchHits  []int
	threadHits []int
	keepHits   map[string]int
}

// applyPatches performs the text patches of spec on job.
func (ps *pkgState) applyPatches(job *fileJob) error {
	for i, p := range ps.spec.Patches {
		if p.File != job.name {
			continue
		}
		lo, hi := 0, len(job.src)
		if p.Decl != "" {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
			if err != nil {
				return err
			}
			found := false
			for _, d := range f.Decls {
				if declMatches(d, p.Decl) {
					lo, hi = fset.Position(d.Pos()).Offset, fset.Position(d.End()).Offset
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: patch %d: decl %q not found", job.name, i, p.Decl)
			}
		}
		scope := string(job.src[lo:hi])
		want := max(p.Count, 1)
		if got := strings.Count(scope, p.Old); got != want {
			return fmt.Errorf("%s: patch %d: %q found %d times, want %d", job.name, i, p.Old, got, want)
		}
		scope = strings.ReplaceAll(scope, p.Old, p.New)
		job.src = slices.Concat(job.src[:lo], []byte(scope), job.src[hi:])
		ps.patchHits[i]++
	}
	return nil
}

func declMatches(d ast.Decl, name string) bool {
	switch d := d.(type) {
	case *ast.FuncDecl:
		return funcName(d) == name
	case *ast.GenDecl:
		for _, s := range d.Specs {
			if slices.Contains(specNames(s), name) {
				return true
			}
		}
	}
	return false
}

func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	t := d.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

func specNames(s ast.Spec) []string {
	switch s := s.(type) {
	case *ast.TypeSpec:
		return []string{s.Name.Name}
	case *ast.ValueSpec:
		var names []string
		for _, n := range s.Names {
			names = append(names, n.Name)
		}
		return names
	}
	return nil
}

// scan records package-level names before any file is rewritten.
func (ps *pkgState) scan(f *ast.File) {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				ps.topNames[d.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				for _, n := range specNames(s) {
					ps.topNames[n] = true
					if d.Tok == token.CONST {
						ps.consts[n] = true
					}
				}
			}
		}
	}
}

// rewriter collects the edits of the generic rules on one parsed file.
type rewriter struct {
	ps    *pkgState
	job   *fileJob
	fset  *token.FileSet
	file  *ast.File
	src   []byte
	edits []edit
}

func (ps *pkgState) rewrite(job *fileJob) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
	if err != nil {
		return err
	}
	rw := &rewriter{ps: ps, job: job, fset: fset, file: f, src: job.src}
	if !ps.spec.Kit {
		rw.stripBuildLines()
	}
	if !job.decls {
		rw.dropDecls()
	}
	for _, fa := range ps.spec.FieldArrays {
		if err := rw.fieldArrays(fa); err != nil {
			return fmt.Errorf("fieldArray %s.%s: %w", fa.Type, fa.Field, err)
		}
	}
	if name := ps.spec.Name; name != "" && !job.isTest {
		rw.edits = append(rw.edits, edit{start: rw.off(f.Name.Pos()), end: rw.off(f.Name.End()), text: name})
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || rw.deleted(fd) {
			continue
		}
		rw.stripFIPS(fd)
		if !job.isTest && !ps.spec.Kit {
			rw.constMakes(fd)
			rw.hoistErrors(fd)
			rw.xorInPlace(fd)
			rw.pointerTables(fd)
			rw.stringWrites(fd)
		}
		if job.isTest {
			if err := rw.quickChecks(fd); err != nil {
				return err
			}
		}
	}
	job.src, err = applyEdits(job.src, rw.edits)
	return err
}

func (rw *rewriter) off(p token.Pos) int  { return rw.fset.Position(p).Offset }
func (rw *rewriter) line(p token.Pos) int { return rw.fset.Position(p).Line }

// deleteRange removes [start,end) widened to whole lines when nothing else shares them.
func (rw *rewriter) deleteRange(start, end int) {
	s, e := start, end
	for s > 0 && (rw.src[s-1] == ' ' || rw.src[s-1] == '\t') {
		s--
	}
	for e < len(rw.src) && (rw.src[e] == ' ' || rw.src[e] == '\t') {
		e++
	}
	if (s == 0 || rw.src[s-1] == '\n') && (e == len(rw.src) || rw.src[e] == '\n') {
		start, end = s, min(e+1, len(rw.src))
	}
	rw.edits = append(rw.edits, edit{start: start, end: end})
}

// deleteNode removes node and a comment group directly above it that starts after floor.
func (rw *rewriter) deleteNode(n ast.Node, doc *ast.CommentGroup, floor token.Pos) {
	start := n.Pos()
	if doc != nil {
		start = doc.Pos()
	} else if cg := rw.commentAbove(n.Pos(), floor); cg != nil {
		start = cg.Pos()
	}
	rw.deleteRange(rw.off(start), rw.off(n.End()))
}

func (rw *rewriter) commentAbove(p, floor token.Pos) *ast.CommentGroup {
	for _, cg := range rw.file.Comments {
		if cg.Pos() > floor && cg.End() < p && rw.line(cg.End())+1 == rw.line(p) {
			return cg
		}
	}
	return nil
}

func (rw *rewriter) deleted(n ast.Node) bool {
	o := rw.off(n.Pos())
	for _, e := range rw.edits {
		if e.text == "" && e.start <= o && o < e.end {
			return true
		}
	}
	return false
}

// stripBuildLines removes build constraints, which file selection already applied,
// and go:generate directives, which refer to upstream generators not ported.
func (rw *rewriter) stripBuildLines() {
	for _, cg := range rw.file.Comments {
		for _, c := range cg.List {
			header := cg.Pos() < rw.file.Package
			if (header && (constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text))) || strings.HasPrefix(c.Text, "//go:generate ") {
				rw.deleteRange(rw.off(c.Pos()), rw.off(c.End()))
			}
		}
	}
}

func (rw *rewriter) dropDecls() {
	keep := rw.ps.spec.KeepDecls
	if rw.job.isTest {
		keep = nil // Tests are ported whole: they only use what they test.
	}
	drop := func(name string) (strict, ok bool) {
		if len(keep) > 0 {
			if slices.Contains(keep, name) {
				rw.ps.keepHits[name]++
				return false, false
			}
			return false, true
		}
		if slices.Contains(rw.ps.spec.DropDecls, name) {
			return true, true
		}
		return false, slices.Contains(dropAlways, name)
	}
	if len(keep) > 0 {
		rw.dropFloatingComments()
	}
	for _, d := range rw.file.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			name := funcName(d)
			if strict, ok := drop(name); ok {
				if strict {
					rw.ps.dropHits[name]++
				}
				rw.deleteNode(d, d.Doc, rw.file.Package)
			}
		case *ast.GenDecl:
			var kill []ast.Spec
			for _, s := range d.Specs {
				for _, n := range specNames(s) {
					if strict, ok := drop(n); ok {
						if strict {
							rw.ps.dropHits[n]++
						}
						kill = append(kill, s)
						break
					}
				}
			}
			switch {
			case len(kill) == 0:
			case len(kill) == len(d.Specs):
				rw.deleteNode(d, d.Doc, rw.file.Package)
			default:
				for _, s := range kill {
					var doc *ast.CommentGroup
					switch s := s.(type) {
					case *ast.ValueSpec:
						doc = s.Doc
					case *ast.TypeSpec:
						doc = s.Doc
					}
					rw.deleteNode(s, doc, d.Lparen)
				}
			}
		}
	}
}

// dropFloatingComments deletes comment groups after the imports that belong to no
// declaration, in KeepDecls mode: they describe code that is gone. Comments of
// declarations go or stay with them.
func (rw *rewriter) dropFloatingComments() {
	var decls [][2]token.Pos // Ranges of declarations with their docs.
	after := rw.file.Name.End()
	for _, d := range rw.file.Decls {
		start := d.Pos()
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Doc != nil {
				start = d.Doc.Pos()
			}
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				after = d.End()
			}
			if d.Doc != nil {
				start = d.Doc.Pos()
			}
		}
		decls = append(decls, [2]token.Pos{start, d.End()})
	}
	for _, cg := range rw.file.Comments {
		if cg.Pos() < after {
			continue
		}
		inside := false
		for _, r := range decls {
			if r[0] <= cg.Pos() && cg.End() <= r[1] {
				inside = true
			}
		}
		if !inside {
			rw.deleteRange(rw.off(cg.Pos()), rw.off(cg.End()))
		}
	}
}

// stripFIPS deletes FIPS indicator/self-test statements and `if <false cond> {}` blocks.
// init functions left empty are deleted whole.
func (rw *rewriter) stripFIPS(fd *ast.FuncDecl) {
	var dels []ast.Stmt
	total := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch n := n.(type) {
		case *ast.BlockStmt:
			list = n.List
		case *ast.CaseClause:
			list = n.Body
		case *ast.CommClause:
			list = n.Body
		default:
			return true
		}
		if n == fd.Body {
			total = len(list)
		}
		for _, s := range list {
			if rw.strippable(s) {
				dels = append(dels, s)
			}
		}
		return true
	})
	if len(dels) == 0 {
		return
	}
	if fd.Recv == nil && fd.Name.Name == "init" && len(dels) == total {
		rw.deleteNode(fd, fd.Doc, rw.file.Package)
		return
	}
	for i, s := range dels {
		nested := false
		for j, o := range dels {
			if i != j && o.Pos() <= s.Pos() && s.End() <= o.End() {
				nested = true
			}
		}
		if !nested {
			rw.deleteNode(s, nil, fd.Body.Lbrace)
		}
	}
}

func (rw *rewriter) strippable(s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		return ok && stripCalls[rw.text(call.Fun)]
	case *ast.IfStmt:
		return s.Init == nil && s.Else == nil && falseConds[rw.text(s.Cond)]
	}
	return false
}

func (rw *rewriter) text(n ast.Node) string {
	return string(rw.src[rw.off(n.Pos()):rw.off(n.End())])
}

// constMakes rewrites every make([]T, C) and make([]T, L, C) with constant C into a
// stack array declared just before the enclosing statement and a slice of it. TinyGo's
// escape analysis only sees fixed-size allocations; they can then also be hoisted.
// Makes in loop, if and switch headers are left alone: moving them would change how
// often fresh memory is produced.
func (rw *rewriter) constMakes(fd *ast.FuncDecl) {
	used := map[string]bool{}
	ast.Inspect(fd, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			used[id.Name] = true
		}
		return true
	})
	var visitList func(list []ast.Stmt)
	var visit func(n ast.Node, stmt ast.Stmt)
	visitList = func(list []ast.Stmt) {
		for _, s := range list {
			visit(s, s)
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
			visit(n.Body, nil)
			return
		case *ast.RangeStmt:
			visit(n.Body, nil)
			return
		case *ast.IfStmt:
			visit(n.Body, nil)
			if n.Else != nil {
				visit(n.Else, nil)
			}
			return
		case *ast.SwitchStmt:
			visit(n.Body, nil)
			return
		case *ast.TypeSwitchStmt:
			visit(n.Body, nil)
			return
		case *ast.SelectStmt:
			visit(n.Body, nil)
			return
		case *ast.FuncLit:
			visit(n.Body, nil)
			return
		case *ast.CallExpr:
			if stmt != nil && !rw.deleted(n) && rw.constMake(n, stmt, used) {
				return
			}
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n || c == nil {
				return c != nil
			}
			visit(c, stmt)
			return false
		})
	}
	visit(fd.Body, nil)
}

func (rw *rewriter) constMake(call *ast.CallExpr, stmt ast.Stmt, used map[string]bool) bool {
	if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "make" || len(call.Args) < 2 {
		return false
	}
	at, ok := call.Args[0].(*ast.ArrayType)
	if !ok || at.Len != nil || !rw.isConst(call.Args[len(call.Args)-1]) {
		return false
	}
	capacity := rw.text(call.Args[len(call.Args)-1])
	length := ""
	if len(call.Args) == 3 {
		length = rw.text(call.Args[1])
	}
	base := makeName(call, stmt) + "Arr"
	name := base
	for i := 2; used[name]; i++ {
		name = base + strconv.Itoa(i)
	}
	used[name] = true
	at0 := rw.off(stmt.Pos())
	rw.edits = append(rw.edits,
		edit{start: at0, end: at0, text: fmt.Sprintf("var %s [%s]%s\n", name, capacity, rw.text(at.Elt))},
		edit{start: rw.off(call.Pos()), end: rw.off(call.End()), text: name + "[:" + length + "]"},
	)
	return true
}

// makeName names the array backing call after the variable it ends up in.
func makeName(call *ast.CallExpr, stmt ast.Stmt) string {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for i, r := range s.Rhs {
			if r == call && len(s.Lhs) == len(s.Rhs) {
				if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
					return id.Name
				}
			}
		}
		if id, ok := s.Lhs[0].(*ast.Ident); ok && len(s.Lhs) == 1 && id.Name != "_" {
			return id.Name
		}
	case *ast.DeclStmt:
		if vs, ok := s.Decl.(*ast.GenDecl).Specs[0].(*ast.ValueSpec); ok && len(vs.Names) == 1 {
			return vs.Names[0].Name
		}
	case *ast.ReturnStmt:
		return "ret"
	}
	return "tmp"
}

// fieldArrays applies fa to the file: the field declaration, every selector of the
// field and composite literals of the type. Selectors are matched by field name,
// so the name must be unique to fa.Type within the package.
//
//	x.f           -> x.acc()           (the slice view x.f[:x.n])
//	len(x.f)      -> x.n               (x side effect free, else len(x.acc()))
//	cap(x.f)      -> len(x.f)          (the array length)
//	x.f = x.f[:k] -> x.n = k
//	T{e}, T{f: e} -> *tFromF(e)        (copying e into the array)
//
// Any other write to the field is an error: patch it first.
func (rw *rewriter) fieldArrays(fa fieldArray) error {
	var failed error
	var walk func(n, parent ast.Node)
	simple := func(e ast.Expr) bool {
		for {
			switch x := e.(type) {
			case *ast.Ident:
				return true
			case *ast.SelectorExpr:
				e = x.X
			default:
				return false
			}
		}
	}
	isField := func(e ast.Expr) (*ast.SelectorExpr, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		return sel, ok && sel.Sel.Name == fa.Field
	}
	walk = func(n, parent ast.Node) {
		if d, ok := n.(ast.Decl); ok && rw.deleted(d) {
			return
		}
		switch n := n.(type) {
		case *ast.TypeSpec:
			if st, ok := n.Type.(*ast.StructType); ok && n.Name.Name == fa.Type {
				for _, f := range st.Fields.List {
					if len(f.Names) == 1 && f.Names[0].Name == fa.Field {
						at, ok := f.Type.(*ast.ArrayType)
						if !ok || at.Len != nil {
							failed = fmt.Errorf("field is not a slice")
							return
						}
						rw.edits = append(rw.edits, edit{start: rw.off(f.Type.Pos()), end: rw.off(f.Type.End()),
							text: fmt.Sprintf("[%s]%s\n\t%s int", fa.Len, rw.text(at.Elt), fa.LenField)})
					}
				}
				return
			}
		case *ast.CompositeLit:
			if id, ok := n.Type.(*ast.Ident); ok && id.Name == fa.Type && len(n.Elts) == 1 {
				e := n.Elts[0]
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					e = kv.Value
				}
				start, text := rw.off(n.Pos()), fmt.Sprintf("*%sFrom%s(", lowerFirst(fa.Type), upperFirst(fa.Field))
				if u, ok := parent.(*ast.UnaryExpr); ok && u.Op == token.AND {
					start, text = rw.off(u.Pos()), fmt.Sprintf("%sFrom%s(", lowerFirst(fa.Type), upperFirst(fa.Field))
				}
				rw.edits = append(rw.edits, edit{start: start, end: rw.off(e.Pos()), text: text},
					edit{start: rw.off(e.End()), end: rw.off(n.End()), text: ")"})
				walk(e, n)
				return
			}
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				sel, ok := isField(l)
				if !ok {
					continue
				}
				se, ok := n.Rhs[i].(*ast.SliceExpr)
				var inner *ast.SelectorExpr
				if ok {
					inner, ok = isField(se.X)
				}
				if !ok || len(n.Lhs) != 1 || se.Low != nil || se.High == nil || se.Slice3 || rw.text(inner.X) != rw.text(sel.X) || !simple(sel.X) {
					failed = fmt.Errorf("unsupported write %q", rw.text(n))
					return
				}
				rw.edits = append(rw.edits,
					edit{start: rw.off(n.Pos()), end: rw.off(se.High.Pos()), text: rw.text(sel.X) + "." + fa.LenField + " = "},
					edit{start: rw.off(se.High.End()), end: rw.off(n.End())})
				walk(se.High, se)
				return
			}
		case *ast.CallExpr:
			if fn, ok := n.Fun.(*ast.Ident); ok && len(n.Args) == 1 && (fn.Name == "len" || fn.Name == "cap") {
				if sel, ok := isField(n.Args[0]); ok {
					switch {
					case fn.Name == "cap":
						rw.edits = append(rw.edits, edit{start: rw.off(n.Pos()), end: rw.off(n.End()), text: "len(" + rw.text(sel) + ")"})
						return
					case simple(sel.X):
						rw.edits = append(rw.edits, edit{start: rw.off(n.Pos()), end: rw.off(n.End()), text: rw.text(sel.X) + "." + fa.LenField})
						return
					}
				}
			}
		case *ast.SelectorExpr:
			if n.Sel.Name == fa.Field {
				if kv, ok := parent.(*ast.KeyValueExpr); ok && kv.Key == n {
					return
				}
				rw.edits = append(rw.edits, edit{start: rw.off(n.Sel.Pos()), end: rw.off(n.Sel.End()), text: fa.Accessor + "()"})
				walk(n.X, n)
				return
			}
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n || c == nil {
				return c != nil
			}
			walk(c, n)
			return false
		})
	}
	walk(rw.file, nil)
	return failed
}

// fieldArrayFile renders the accessors and constructors of the package's field arrays.
func (ps *pkgState) fieldArrayFile() []byte {
	if len(ps.spec.FieldArrays) == 0 {
		return nil
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n\n", ps.pkgName)
	for _, fa := range ps.spec.FieldArrays {
		fmt.Fprintf(&b, "// %[2]s returns the %[3]s in use, a slice of x's array.\nfunc (x *%[1]s) %[2]s() []%[5]s { return x.%[3]s[:x.%[4]s] }\n\n", fa.Type, fa.Accessor, fa.Field, fa.LenField, fa.Elem)
		fmt.Fprintf(&b, "// %[1]sFrom%[2]s returns a new %[3]s holding a copy of %[4]s. It panics if %[4]s does not fit.\nfunc %[1]sFrom%[2]s(%[4]s []%[6]s) *%[3]s {\n\tx := &%[3]s{%[5]s: len(%[4]s)}\n\tcopy(x.%[4]s[:len(%[4]s)], %[4]s)\n\treturn x\n}\n\n",
			lowerFirst(fa.Type), upperFirst(fa.Field), fa.Type, fa.Field, fa.LenField, fa.Elem)
	}
	return b.Bytes()
}

func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }
func upperFirst(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// pointerTables rewrites a table of pointers to new(T) locals,
//
//	a := new(T); b := new(T); tbl := []*T{a, b, a}; ... tbl[i] ...
//
// into values in one array and a table of indices into it,
//
//	var tblVals [2]T; a := &tblVals[0]; b := &tblVals[1]; tbl := [...]uint8{0, 1, 0}; ... &tblVals[tbl[i]] ...
//
// TinyGo treats storing a pointer into memory as an escape, which heap allocates
// every table member; indexing into an array does not store pointers.
func (rw *rewriter) pointerTables(fd *ast.FuncDecl) {
	news := map[string]*ast.AssignStmt{} // Local -> its `x := new(T)` statement.
	newType := map[string]string{}
	for _, s := range fd.Body.List {
		as, ok := s.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		call, ok2 := as.Rhs[0].(*ast.CallExpr)
		if !ok || !ok2 || rw.text(call.Fun) != "new" || len(call.Args) != 1 {
			continue
		}
		news[id.Name] = as
		newType[id.Name] = rw.text(call.Args[0])
	}
	for _, s := range fd.Body.List {
		as, ok := s.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		tbl, ok := as.Lhs[0].(*ast.Ident)
		lit, ok2 := as.Rhs[0].(*ast.CompositeLit)
		if !ok || !ok2 {
			continue
		}
		at, ok := lit.Type.(*ast.ArrayType)
		if !ok || at.Len != nil {
			continue
		}
		star, ok := at.Elt.(*ast.StarExpr)
		if !ok {
			continue
		}
		elem := rw.text(star.X)
		index := map[string]int{}
		var order []string
		var idx []string
		valid := len(lit.Elts) > 0
		for _, e := range lit.Elts {
			id, ok := e.(*ast.Ident)
			if !ok || newType[id.Name] != elem || news[id.Name].Pos() > as.Pos() {
				valid = false
				break
			}
			if _, seen := index[id.Name]; !seen {
				index[id.Name] = len(order)
				order = append(order, id.Name)
			}
			idx = append(idx, strconv.Itoa(index[id.Name]))
		}
		if !valid || len(order) > 256 {
			continue
		}
		// Every use of tbl must be tbl[i].
		var uses []*ast.IndexExpr
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if ix, ok := n.(*ast.IndexExpr); ok {
				if id, ok := ix.X.(*ast.Ident); ok && id.Obj == tbl.Obj {
					uses = append(uses, ix)
					return false
				}
			}
			if id, ok := n.(*ast.Ident); ok && id.Obj == tbl.Obj && id != tbl {
				valid = false
			}
			return true
		})
		if !valid {
			continue
		}
		vals := tbl.Name + "Vals"
		first := as
		for _, name := range order {
			if news[name].Pos() < first.Pos() {
				first = news[name]
			}
		}
		at0 := rw.off(first.Pos())
		rw.edits = append(rw.edits, edit{start: at0, end: at0, text: fmt.Sprintf("var %s [%d]%s\n", vals, len(order), elem)})
		for i, name := range order {
			st := news[name]
			rw.edits = append(rw.edits, edit{start: rw.off(st.Rhs[0].Pos()), end: rw.off(st.Rhs[0].End()), text: fmt.Sprintf("&%s[%d]", vals, i)})
		}
		rw.edits = append(rw.edits, edit{start: rw.off(lit.Pos()), end: rw.off(lit.End()), text: "[...]uint8{" + strings.Join(idx, ", ") + "}"})
		for _, ix := range uses {
			rw.edits = append(rw.edits, edit{start: rw.off(ix.Pos()), end: rw.off(ix.End()), text: fmt.Sprintf("&%s[%s]", vals, rw.text(ix))})
		}
	}
}

// castToTest turns job, an upstream cast.go, into cast_test.go: the FIPS 140-3
// start-up self-tests, each a fips140.CAST(name, f) call, become subtests of
// TestCAST, so their known answers check the port. Declarations holding CAST
// calls are replaced; the helpers they use stay.
func castToTest(job *fileJob) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
	if err != nil {
		return err
	}
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	text := func(n ast.Node) string { return string(job.src[off(n.Pos()):off(n.End())]) }
	var cases strings.Builder
	var edits []edit
	for _, d := range f.Decls {
		n := 0
		ast.Inspect(d, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CAST" {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "fips140" {
					fmt.Fprintf(&cases, "\t\t{%s, %s},\n", text(call.Args[0]), text(call.Args[1]))
					n++
					return false
				}
			}
			return true
		})
		if n > 0 {
			start := d.Pos()
			if gd, ok := d.(*ast.GenDecl); ok && gd.Doc != nil {
				start = gd.Doc.Pos()
			} else if fd, ok := d.(*ast.FuncDecl); ok && fd.Doc != nil {
				start = fd.Doc.Pos()
			}
			edits = append(edits, edit{start: off(start), end: off(d.End())})
		}
	}
	if cases.Len() == 0 {
		return fmt.Errorf("%s: no fips140.CAST calls", job.name)
	}
	var imp *ast.GenDecl
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT && gd.Lparen.IsValid() {
			imp = gd
			break
		}
	}
	if imp == nil {
		return fmt.Errorf("%s: no import block", job.name)
	}
	edits = append(edits, edit{start: off(imp.Rparen), end: off(imp.Rparen), text: "\t\"testing\"\n"})
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	src, err := applyEdits(job.src, edits)
	if err != nil {
		return err
	}
	job.src = append(src, "\n// TestCAST runs the known-answer self-tests the FIPS 140-3 module runs at start-up.\n"+
		"func TestCAST(t *testing.T) {\n\tfor _, c := range []struct {\n\t\tname string\n\t\tf    func() error\n\t}{\n"+
		cases.String()+"\t} {\n\t\tt.Run(c.name, func(t *testing.T) {\n\t\t\tif err := c.f(); err != nil {\n\t\t\t\tt.Fatal(err)\n\t\t\t}\n\t\t})\n\t}\n}\n"...)
	job.name, job.isTest = "cast_test.go", true
	return nil
}

// quickChecks rewrites testing/quick's Check(f, config) to CheckN of
// internal/lcryptotest/quick, where N is the arity of f: TinyGo's reflect cannot
// inspect or call function types, so the arity must be known when compiling.
// f is a function literal, a variable assigned one in fd, a top-level function
// of the file, or a call of a top-level function returning a function.
func (rw *rewriter) quickChecks(fd *ast.FuncDecl) error {
	var err error
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || err != nil {
			return err == nil
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Check" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "quick" {
			return true
		}
		ft := rw.funcTypeOf(call.Args[0], fd)
		if ft == nil {
			err = fmt.Errorf("%s: cannot tell the arity of the function quick.Check checks", rw.fset.Position(call.Pos()))
			return false
		}
		arity := 0
		for _, f := range ft.Params.List {
			arity += max(1, len(f.Names))
		}
		rw.edits = append(rw.edits, edit{start: rw.off(sel.Sel.Pos()), end: rw.off(sel.Sel.End()), text: fmt.Sprintf("Check%d", arity)})
		return true
	})
	return err
}

// funcTypeOf finds the type of function-valued expression e syntactically, see quickChecks.
func (rw *rewriter) funcTypeOf(e ast.Expr, fd *ast.FuncDecl) *ast.FuncType {
	topLevel := func(name string) *ast.FuncDecl {
		for _, d := range rw.file.Decls {
			if f, ok := d.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == name {
				return f
			}
		}
		return nil
	}
	switch e := e.(type) {
	case *ast.FuncLit:
		return e.Type
	case *ast.Ident:
		var ft *ast.FuncType
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == e.Name {
					if lit, ok := as.Rhs[0].(*ast.FuncLit); ok {
						ft = lit.Type
					}
				}
			}
			return ft == nil
		})
		if ft == nil {
			if f := topLevel(e.Name); f != nil {
				ft = f.Type
			}
		}
		return ft
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok {
			if f := topLevel(id.Name); f != nil && f.Type.Results != nil && len(f.Type.Results.List) == 1 {
				ft, _ := f.Type.Results.List[0].Type.(*ast.FuncType)
				return ft
			}
		}
	}
	return nil
}

// stringWrites rewrites w.Write([]byte(s)) into a write of s's bytes in place,
// w.Write(unsafe.Slice(unsafe.StringData(s), len(s))): TinyGo heap allocates
// the conversion's copy. Write implementations must not modify or retain their
// argument (io.Writer), so sharing s's memory is safe.
func (rw *rewriter) stringWrites(fd *ast.FuncDecl) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || rw.deleted(call) || len(call.Args) != 1 {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Write" {
			return true
		}
		conv, ok := call.Args[0].(*ast.CallExpr)
		if !ok || len(conv.Args) != 1 || rw.text(conv.Fun) != "[]byte" {
			return true
		}
		s := rw.text(conv.Args[0])
		if _, isLit := conv.Args[0].(*ast.Ident); !isLit {
			return true // Evaluate s once: identifiers only.
		}
		rw.edits = append(rw.edits, edit{start: rw.off(conv.Pos()), end: rw.off(conv.End()),
			text: fmt.Sprintf("unsafe.Slice(unsafe.StringData(%s), len(%s))", s, s)})
		return false
	})
}

// xorInPlace rewrites subtle.XORBytes(a, a, b) into subtle.XORInto(a, b), which has no
// overlap check: the pointer to integer conversion of that check makes TinyGo heap
// allocate every buffer passed in.
func (rw *rewriter) xorInPlace(fd *ast.FuncDecl) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || rw.deleted(call) || !strings.HasSuffix(rw.text(call.Fun), "XORBytes") || len(call.Args) != 3 {
			return true
		}
		if rw.text(call.Args[0]) != rw.text(call.Args[1]) {
			return true
		}
		fn := strings.TrimSuffix(rw.text(call.Fun), "XORBytes") + "XORInto"
		repl := fmt.Sprintf("%s(%s, %s)", fn, rw.text(call.Args[0]), rw.text(call.Args[2]))
		rw.edits = append(rw.edits, edit{start: rw.off(call.Pos()), end: rw.off(call.End()), text: repl})
		return false
	})
}

func (rw *rewriter) isConst(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.INT
	case *ast.Ident:
		return rw.ps.consts[e.Name]
	case *ast.ParenExpr:
		return rw.isConst(e.X)
	case *ast.BinaryExpr:
		return rw.isConst(e.X) && rw.isConst(e.Y)
	}
	return false
}

// hoistErrors replaces errors.New("literal") in function bodies with a package-level
// variable so that returning the error does not allocate. A message built at run
// time, errors.New("prefix: " + detail), keeps its constant prefix only.
func (rw *rewriter) hoistErrors(fd *ast.FuncDecl) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || rw.deleted(call) || rw.text(call.Fun) != "errors.New" || len(call.Args) != 1 {
			return true
		}
		arg := call.Args[0]
		// errors.New("prefix: " + detail) formats detail at run time, which
		// allocates: keep the constant prefix only.
		dynamic := false
		for {
			bin, ok := arg.(*ast.BinaryExpr)
			if !ok || bin.Op != token.ADD {
				break
			}
			arg, dynamic = bin.X, true
		}
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		msg, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if dynamic {
			msg = strings.TrimRight(msg, ": ")
		}
		name := rw.ps.errVar(msg)
		rw.edits = append(rw.edits, edit{start: rw.off(call.Pos()), end: rw.off(call.End()), text: name})
		return false
	})
}

func (ps *pkgState) errVar(msg string) string {
	if name, ok := ps.errVars[msg]; ok {
		return name
	}
	_, body, found := strings.Cut(msg, ": ")
	if !found {
		body = msg
	}
	var sb strings.Builder
	sb.WriteString("err")
	body = strings.ReplaceAll(body, "'", "")
	words := strings.FieldsFunc(body, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for i, w := range words {
		if i == 5 {
			break
		}
		sb.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	base := sb.String()
	name := base
	for n := 2; ps.topNames[name]; n++ {
		name = base + strconv.Itoa(n)
	}
	ps.topNames[name] = true
	ps.errVars[msg] = name
	ps.errOrder = append(ps.errOrder, msg)
	return name
}

// errorsFile renders the hoisted error variables of the package, or nil if none.
func (ps *pkgState) errorsFile() []byte {
	if len(ps.errOrder) == 0 {
		return nil
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n\nimport \"errors\"\n\n// Errors hoisted out of function bodies so returning them does not allocate.\nvar (\n", ps.pkgName)
	for _, msg := range ps.errOrder {
		fmt.Fprintf(&b, "\t%s = errors.New(%s)\n", ps.errVars[msg], strconv.Quote(msg))
	}
	b.WriteString(")\n")
	return b.Bytes()
}

// fixImports removes unused imports, remaps ported ones and adds known missing ones.
func (ps *pkgState) fixImports(job *fileJob) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				used[id.Name] = true
			}
		}
		return true
	})
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	var edits []edit
	have := map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		var kill []*ast.ImportSpec
		for _, s := range gd.Specs {
			is := s.(*ast.ImportSpec)
			p, _ := strconv.Unquote(is.Path.Value)
			name := importName(is, p)
			if (name != "_" && name != "." && !used[name]) || (name == "_" && stripImports[p]) {
				kill = append(kill, is)
				continue
			}
			have[name] = true
			np, err := ps.mapImport(p, job.isTest || ps.spec.Kit)
			if err != nil {
				return fmt.Errorf("%s: %w", job.name, err)
			}
			if np != p {
				text := strconv.Quote(np)
				if is.Name == nil && path.Base(np) != name {
					text = name + " " + text
				}
				edits = append(edits, edit{start: off(is.Path.Pos()), end: off(is.Path.End()), text: text})
			}
		}
		if len(kill) == len(gd.Specs) {
			edits = append(edits, edit{start: off(gd.Pos()), end: off(gd.End())})
			continue
		}
		for _, is := range kill {
			// The whole line, so no blank line splits the block into groups.
			start, end := off(is.Pos()), off(is.End())
			for start > 0 && (job.src[start-1] == ' ' || job.src[start-1] == '\t') {
				start--
			}
			if end < len(job.src) && job.src[end] == '\n' && start > 0 && job.src[start-1] == '\n' {
				end++
			}
			edits = append(edits, edit{start: start, end: end})
		}
	}
	var add []string
	for name := range used {
		if have[name] || f.Scope.Lookup(name) != nil {
			continue
		}
		if p, ok := knownImport(name); ok && !ps.topNames[name] {
			add = append(add, strconv.Quote(p))
		}
	}
	sort.Strings(add)
	if len(add) > 0 {
		// Into the first surviving import block, else a new one.
		var block *ast.GenDecl
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT && gd.Lparen.IsValid() && len(gd.Specs) > 0 {
				if n := countKilled(gd, edits, off); n < len(gd.Specs) {
					block = gd
					break
				}
			}
		}
		if block != nil {
			at := off(block.Lparen) + 1
			edits = append(edits, edit{start: at, end: at, text: "\n" + strings.Join(add, "\n")})
		} else {
			at := off(f.Name.End())
			edits = append(edits, edit{start: at, end: at, text: "\n\nimport (\n" + strings.Join(add, "\n") + "\n)"})
		}
	}
	job.src, err = applyEdits(job.src, edits)
	return err
}

// countKilled counts the specs of gd that edits delete.
func countKilled(gd *ast.GenDecl, edits []edit, off func(token.Pos) int) int {
	n := 0
	for _, sp := range gd.Specs {
		for _, e := range edits {
			if e.text == "" && e.start <= off(sp.Pos()) && off(sp.End()) <= e.end {
				n++
				break
			}
		}
	}
	return n
}

func importName(is *ast.ImportSpec, p string) string {
	if is.Name != nil {
		return is.Name.Name
	}
	base := path.Base(p)
	if len(base) > 1 && base[0] == 'v' && strings.Trim(base[1:], "0123456789") == "" {
		base = path.Base(path.Dir(p))
	}
	return base
}

// mapImport maps upstream import p. Test code, isTest, may also import the test
// support packages and non-internal std packages.
func (ps *pkgState) mapImport(p string, isTest bool) (string, error) {
	if strings.HasPrefix(p, modulePath+"/"+stdDir+"/") || isTest && strings.HasPrefix(p, modulePath+"/"+kitDir+"/") {
		return p, nil // Already mapped.
	}
	if dst, ok := kitImportMap[p]; ok && isTest {
		return modulePath + "/" + dst, nil
	}
	if dst, ok := importMap[p]; ok {
		return modulePath + "/" + stdDir + "/" + dst, nil
	}
	if !isTest {
		if dst, ok := importMapNonTest[p]; ok {
			return modulePath + "/" + stdDir + "/" + dst, nil
		}
		if allowedStd[p] {
			return p, nil
		}
		return "", fmt.Errorf("import %q not allowed in generated code", p)
	}
	if strings.HasPrefix(p, "golang.org/x/crypto") || strings.Contains(p, "internal/") {
		return "", fmt.Errorf("test import %q has no port", p)
	}
	return p, nil
}

func knownImport(name string) (string, bool) {
	switch name {
	case "unsafe", "errors", "strconv":
		return name, true
	case "binary":
		return "encoding/binary", true
	case "bits":
		return "math/bits", true
	}
	for _, dst := range importMap {
		if path.Base(dst) == name {
			return modulePath + "/" + stdDir + "/" + dst, true
		}
	}
	for _, dst := range kitImportMap { // Test support; mapImport rejects it outside tests.
		if path.Base(dst) == name {
			return modulePath + "/" + dst, true
		}
	}
	return "", false
}

var errNoPackage = errors.New("no files survived selection")

// finish prepends the generated header and gofmts. The first line marks the
// file for readers; the second, in the form Go tools recognize
// (^// Code generated .* DO NOT EDIT\.$), says what it was generated from.
func finish(job *fileJob) ([]byte, error) {
	what := "from " + job.origin
	switch {
	case job.decls:
		what = "declarations added to " + job.origin
	case job.fields:
		what = "field array accessors for " + job.origin
	case job.variants:
		what = "allocation-free variants of functions in " + job.origin
	case job.hoisted:
		what = "errors.New calls hoisted from " + job.origin
	}
	hdr := header + "\n// Code generated by lcryptogen " + what + ". DO NOT EDIT.\n\n"
	out, err := format.Source(append([]byte(hdr), job.src...))
	if err != nil {
		return nil, fmt.Errorf("%s: gofmt: %w", job.name, err)
	}
	return out, nil
}

// header is the first line of every generated file, which the generator
// alone deletes or overwrites.
const header = "// DO NOT EDIT; generated by lcryptogen with `lcryptogen generate`."

const headerPrefix = header

func parseFile(job *fileJob) (*ast.File, error) {
	return parser.ParseFile(token.NewFileSet(), job.name, job.src, parser.ParseComments)
}

// threadParams adds a parameter to the functions of t and passes it at every call site
// in the package, so that helpers can reach scratch space of their caller's struct.
func (ps *pkgState) threadParams(job *fileJob) error {
	if len(ps.spec.Threads) == 0 {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
	if err != nil {
		return err
	}
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	var edits []edit
	for ti, t := range ps.spec.Threads {
		arg, _, _ := strings.Cut(t.Param, " ")
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !slices.Contains(t.Funcs, fd.Name.Name) {
				continue
			}
			sep := ", "
			if fd.Type.Params.NumFields() == 0 {
				sep = ""
			}
			at := off(fd.Type.Params.Opening) + 1
			edits = append(edits, edit{start: at, end: at, text: t.Param + sep})
			ps.threadHits[ti]++
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && slices.Contains(t.Funcs, id.Name) {
				sep := ", "
				if len(call.Args) == 0 {
					sep = ""
				}
				at := off(call.Lparen) + 1
				edits = append(edits, edit{start: at, end: at, text: arg + sep})
			}
			return true
		})
	}
	job.src, err = applyEdits(job.src, edits)
	return err
}

// scratchField is a hoisted local variable become struct field.
type scratchField struct{ name, typ string }

// hoistLocals moves the local variables named by spec.Hoists into a scratch struct
// embedded in the type that owns them. TinyGo heap allocates locals whose address
// reaches an alias check, a variadic call or a closure; struct fields are already
// allocated. It runs across the whole package: fields first, then the owning types.
func (ps *pkgState) hoistLocals(jobs []*fileJob) error {
	if len(ps.spec.Hoists) == 0 {
		return nil
	}
	fields := map[string][]scratchField{} // Owning type -> fields in first-seen order.
	hits := make([]int, len(ps.spec.Hoists))
	for _, job := range jobs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
		if err != nil {
			return err
		}
		rw := &rewriter{ps: ps, job: job, fset: fset, file: f, src: job.src}
		for hi, h := range ps.spec.Hoists {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || funcName(fd) != h.Func {
					continue
				}
				hits[hi]++
				if err := rw.hoist(fd, h, fields); err != nil {
					return fmt.Errorf("%s: hoist %s: %w", job.name, h.Func, err)
				}
			}
		}
		if job.src, err = applyEdits(job.src, rw.edits); err != nil {
			return err
		}
	}
	for i, n := range hits {
		if n == 0 {
			return fmt.Errorf("hoist of %s matched no function", ps.spec.Hoists[i].Func)
		}
	}
	types := make([]string, 0, len(fields))
	for typ := range fields {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		if err := ps.addScratch(jobs, typ, fields[typ]); err != nil {
			return err
		}
	}
	return nil
}

func scratchType(owner string) string {
	return "scratch" + strings.ToUpper(owner[:1]) + owner[1:]
}

func (rw *rewriter) hoist(fd *ast.FuncDecl, h hoist, fields map[string][]scratchField) error {
	want := map[string]string{} // Variable -> field.
	for _, v := range h.Vars {
		name, field, ok := strings.Cut(v, ":")
		if !ok {
			field = name
		}
		want[name] = field
	}
	decls := map[*ast.Object]string{} // Hoisted object -> variable name.
	found := map[string]bool{}
	var failed error
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeclStmt)
		if !ok {
			return true
		}
		gd := ds.Decl.(*ast.GenDecl)
		var lines []string
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			hoisted := 0
			for _, id := range vs.Names {
				if _, ok := want[id.Name]; ok && !found[id.Name] {
					hoisted++
				}
			}
			if hoisted == 0 {
				continue
			}
			if hoisted != len(vs.Names) || len(gd.Specs) != 1 || vs.Values != nil || vs.Type == nil {
				failed = fmt.Errorf("declaration of %s must be a lone `var names T`", vs.Names[0].Name)
				return false
			}
			typ := rw.text(vs.Type)
			for _, id := range vs.Names {
				field := want[id.Name]
				if err := addField(fields, h.Type, scratchField{field, typ}); err != nil {
					failed = err
					return false
				}
				found[id.Name] = true
				decls[id.Obj] = id.Name
				lines = append(lines, fmt.Sprintf("%s := &%s.scratch.%s\n*%s = %s{}", id.Name, h.Via, field, id.Name, typ))
			}
		}
		if lines != nil {
			rw.edits = append(rw.edits, edit{start: rw.off(ds.Pos()), end: rw.off(ds.End()), text: strings.Join(lines, "\n")})
		}
		return true
	})
	if failed != nil {
		return failed
	}
	for name := range want {
		if !found[name] {
			return fmt.Errorf("var %s not declared", name)
		}
	}
	// Uses: &x -> x; indexing, slicing, selectors, len and range work through the pointer; anything else -> (*x).
	var walk func(n, parent ast.Node)
	walk = func(n, parent ast.Node) {
		if id, ok := n.(*ast.Ident); ok {
			if _, ok := decls[id.Obj]; !ok || id.Obj.Decl == nil || rw.isDeclIdent(id) {
				return
			}
			switch p := parent.(type) {
			case *ast.UnaryExpr:
				if p.Op == token.AND {
					rw.edits = append(rw.edits, edit{start: rw.off(p.Pos()), end: rw.off(p.End()), text: id.Name})
					return
				}
			case *ast.IndexExpr, *ast.SliceExpr, *ast.SelectorExpr:
				return
			case *ast.RangeStmt:
				if p.X == id {
					return
				}
			case *ast.CallExpr:
				if fn, ok := p.Fun.(*ast.Ident); ok && (fn.Name == "len" || fn.Name == "cap") {
					return
				}
			}
			rw.edits = append(rw.edits, edit{start: rw.off(id.Pos()), end: rw.off(id.End()), text: "(*" + id.Name + ")"})
			return
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n || c == nil {
				return c != nil
			}
			walk(c, n)
			return false
		})
	}
	walk(fd.Body, fd)
	return nil
}

// isDeclIdent reports whether id is the name in its own declaration.
func (rw *rewriter) isDeclIdent(id *ast.Ident) bool {
	vs, ok := id.Obj.Decl.(*ast.ValueSpec)
	return ok && slices.Contains(vs.Names, id)
}

func addField(fields map[string][]scratchField, owner string, sf scratchField) error {
	for _, have := range fields[owner] {
		if have.name == sf.name {
			if have.typ != sf.typ {
				return fmt.Errorf("scratch field %s.%s declared as %s and %s", owner, sf.name, have.typ, sf.typ)
			}
			return nil // Shared by functions that never run nested.
		}
	}
	fields[owner] = append(fields[owner], sf)
	return nil
}

// addScratch declares the scratch struct of owner and embeds it as field scratch.
func (ps *pkgState) addScratch(jobs []*fileJob, owner string, fields []scratchField) error {
	for _, job := range jobs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE || len(gd.Specs) != 1 {
				continue
			}
			ts := gd.Specs[0].(*ast.TypeSpec)
			st, ok := ts.Type.(*ast.StructType)
			if !ok || ts.Name.Name != owner {
				continue
			}
			var b strings.Builder
			fmt.Fprintf(&b, "\n\n// %s holds locals hoisted out of function frames by lcryptogen\n// so that they are never heap allocated. Not safe for concurrent use.\ntype %s struct {\n", scratchType(owner), scratchType(owner))
			for _, sf := range fields {
				fmt.Fprintf(&b, "\t%s %s\n", sf.name, sf.typ)
			}
			b.WriteString("}")
			closing := fset.Position(st.Fields.Closing).Offset
			end := fset.Position(gd.End()).Offset
			job.src, err = applyEdits(job.src, []edit{
				{start: closing, end: closing, text: "\n\n\tscratch " + scratchType(owner) + "\n"},
				{start: end, end: end, text: b.String()},
			})
			return err
		}
	}
	return fmt.Errorf("struct type %s not found", owner)
}
