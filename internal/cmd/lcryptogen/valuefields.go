package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// valueFields turns the pointer fields of the spec's ValueFields struct types
// into value fields, and named arrays of pointers to those types into arrays of
// values. Upstream builds such structs with new(E) per field,
//
//	type P struct{ x, y *E }
//	func NewP() *P { return &P{x: new(E), y: new(E).One()} }
//	... p.x.Mul(q.x, q.y) ... table[i].Add(table[j], q) ...
//
// which TinyGo heap allocates: storing a pointer into memory is an escape. The
// rule yields
//
//	type P struct{ x, y E }
//	func NewP() *P { v := &P{}; v.y.One(); return v }
//	... p.x.Mul(&q.x, &q.y) ... table[i].Add(&table[j], q) ...
//
// The fields must be owned: initialized with new(E), possibly followed by method
// calls, in a `return &P{...}` literal and never assigned. Uses are resolved with
// go/types: a field or array element becomes addressed (&) where its pointer was
// used as a value, and stays as is where it is a method receiver.
func (ts *typedState) valueFields(ps *pkgState, jobs []*fileJob) error {
	if len(ps.spec.ValueFields) == 0 {
		return nil
	}
	// Type check the generated files alone. Hand-written overlays are written
	// against the rewritten fields and would not check; errors are tolerated
	// as long as the uses resolve.
	fset := token.NewFileSet()
	var files []*ast.File
	byJob := map[*fileJob]*ast.File{}
	for _, job := range jobs {
		if job.isTest {
			continue
		}
		f, err := parser.ParseFile(fset, job.name, job.src, parser.ParseComments)
		if err != nil {
			return err
		}
		files = append(files, f)
		byJob[job] = f
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Uses:       map[*ast.Ident]types.Object{},
		Defs:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: ts, Error: func(error) {}}
	pkg, _ := conf.Check(modulePath+"/"+stdDir+"/"+ps.spec.Dst, fset, files, info)

	targets := map[types.Type]bool{} // The struct types, as *types.Named.
	fields := map[*types.Var]bool{}  // Their pointer fields.
	for _, name := range ps.spec.ValueFields {
		tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			return fmt.Errorf("ValueFields %s: no such type", name)
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			return fmt.Errorf("ValueFields %s: not a struct", name)
		}
		targets[tn.Type()] = true
		for i := 0; i < st.NumFields(); i++ {
			if _, ok := st.Field(i).Type().(*types.Pointer); ok {
				fields[st.Field(i)] = true
			}
		}
	}
	arrays := map[types.Type]bool{} // Named arrays of pointers to targets.
	for _, name := range pkg.Scope().Names() {
		tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		if at, ok := tn.Type().Underlying().(*types.Array); ok {
			if pt, ok := at.Elem().(*types.Pointer); ok && targets[pt.Elem()] {
				arrays[tn.Type()] = true
			}
		}
	}
	isArray := func(e ast.Expr) bool {
		t := info.TypeOf(e)
		if pt, ok := t.(*types.Pointer); ok {
			t = pt.Elem()
		}
		return t != nil && arrays[t]
	}
	// isUse reports whether e reads a field or array element made a value.
	isUse := func(e ast.Node) bool {
		switch e := e.(type) {
		case *ast.SelectorExpr:
			sel := info.Selections[e]
			if sel == nil || sel.Kind() != types.FieldVal {
				return false
			}
			v, _ := sel.Obj().(*types.Var)
			return fields[v]
		case *ast.IndexExpr:
			return isArray(e.X)
		}
		return false
	}

	for _, job := range jobs {
		f := byJob[job]
		if f == nil {
			continue
		}
		off := func(p token.Pos) int { return fset.Position(p).Offset }
		text := func(n ast.Node) string { return string(job.src[off(n.Pos()):off(n.End())]) }
		var edits []edit
		var failed error
		fail := func(n ast.Node, format string, args ...any) {
			if failed == nil {
				failed = fmt.Errorf("%s: ValueFields: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...))
			}
		}
		unstar := func(e ast.Expr) {
			if star, ok := e.(*ast.StarExpr); ok {
				edits = append(edits, edit{start: off(star.Star), end: off(star.Star) + 1})
			}
		}
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, n)
			switch n := n.(type) {
			case *ast.TypeSpec:
				t := info.Defs[n.Name]
				if t == nil {
					break
				}
				if targets[t.Type()] {
					for _, fl := range n.Type.(*ast.StructType).Fields.List {
						for _, name := range fl.Names {
							if v, _ := info.Defs[name].(*types.Var); fields[v] {
								unstar(fl.Type)
								break
							}
						}
					}
				} else if arrays[t.Type()] {
					unstar(n.Type.(*ast.ArrayType).Elt)
				}
			case *ast.ReturnStmt:
				if len(n.Results) != 1 {
					break
				}
				u, ok := n.Results[0].(*ast.UnaryExpr)
				if !ok || u.Op != token.AND {
					break
				}
				lit, ok := u.X.(*ast.CompositeLit)
				if !ok || !targets[info.TypeOf(lit)] {
					break
				}
				var keep, init []string
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						fail(lit, "unkeyed literal")
						return false
					}
					key := text(kv.Key)
					chain, ok := newChain(kv.Value, text)
					if !ok {
						keep = append(keep, text(elt))
						continue
					}
					if chain != "" {
						init = append(init, "v."+key+chain)
					}
				}
				fd := enclosingFunc(stack)
				if fd == nil || usesIdent(fd, "v") {
					fail(n, "cannot name the new value v")
					return false
				}
				repl := fmt.Sprintf("v := &%s{%s}\n", text(lit.Type), strings.Join(keep, ", "))
				for _, s := range init {
					repl += s + "\n"
				}
				repl += "return v"
				edits = append(edits, edit{start: off(n.Pos()), end: off(n.End()), text: repl})
				stack = stack[:len(stack)-1]
				return false
			case *ast.CompositeLit:
				if targets[info.TypeOf(n)] {
					for _, elt := range n.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if _, isNew := newChain(kv.Value, text); isNew {
								fail(n, "field initialized outside `return &%s{...}`", text(n.Type))
							}
						}
					}
				}
				if isArray(n) {
					fail(n, "array literal")
				}
			case *ast.SelectorExpr, *ast.IndexExpr:
				if !isUse(n) {
					break
				}
				switch p := parent.(type) {
				case *ast.SelectorExpr:
					// Receiver or operand of a selector: addressable, auto-addressed.
				case *ast.StarExpr:
					edits = append(edits, edit{start: off(p.Star), end: off(p.Star) + 1})
				case *ast.KeyValueExpr:
					if p.Key == n {
						break
					}
					edits = append(edits, edit{start: off(n.Pos()), end: off(n.Pos()), text: "&"})
				case *ast.AssignStmt:
					for _, l := range p.Lhs {
						if l == n {
							fail(n, "assignment to %s", text(n))
						}
					}
					edits = append(edits, edit{start: off(n.Pos()), end: off(n.Pos()), text: "&"})
				case *ast.BinaryExpr:
					fail(n, "comparison of %s", text(n))
				default:
					edits = append(edits, edit{start: off(n.Pos()), end: off(n.Pos()), text: "&"})
				}
			}
			return true
		})
		if failed != nil {
			return failed
		}
		sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
		src, err := applyEdits(job.src, edits)
		if err != nil {
			return fmt.Errorf("%s: %w", job.name, err)
		}
		job.src = src
	}
	return nil
}

// newChain reports whether e is new(E) followed by zero or more method calls,
// returning the calls, i.e. ".One()".
func newChain(e ast.Expr, text func(ast.Node) string) (chain string, ok bool) {
	var calls []string
	for {
		call, isCall := e.(*ast.CallExpr)
		if !isCall {
			return "", false
		}
		if fn, isID := call.Fun.(*ast.Ident); isID && fn.Name == "new" && len(call.Args) == 1 {
			for i, j := 0, len(calls)-1; i < j; i, j = i+1, j-1 {
				calls[i], calls[j] = calls[j], calls[i]
			}
			return strings.Join(calls, ""), true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return "", false
		}
		calls = append(calls, text(call)[len(text(sel.X)):])
		e = sel.X
	}
}

func enclosingFunc(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if fd, ok := stack[i].(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

func usesIdent(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}
