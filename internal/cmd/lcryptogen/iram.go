package main

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"slices"
	"strings"
)

// srcEdit replaces src[start:end] with text.
type srcEdit struct {
	start, end int
	text       string
}

// markIRAM puts the functions of spec.IRAM in section .text.iram.<pkg>, which
// the TinyGo ESP linker scripts load into IRAM and other scripts keep in flash.
// It counts matches in hits.
func markIRAM(spec *pkgSpec, name string, src []byte, hits map[string]int) ([]byte, error) {
	if len(spec.IRAM) == 0 || strings.HasSuffix(name, "_test.go") {
		return src, nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	var edits []srcEdit
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !slices.Contains(spec.IRAM, funcName(fd)) {
			continue
		}
		hits[funcName(fd)]++
		if call, ok := spec.IRAMBody[funcName(fd)]; ok {
			edits = append(edits, srcEdit{off(fd.Body.Lbrace), off(fd.Body.End()), "{\n\t" + call + "\n}"})
			continue
		}
		pragma := "//go:section .text.iram." + spec.Dst + "\n//go:noinline\n"
		if fd.Doc != nil {
			pragma = "//\n" + pragma
		}
		edits = append(edits, srcEdit{off(fd.Type.Func), off(fd.Type.Func), pragma})
	}
	if len(edits) == 0 {
		return src, nil
	}
	edits = append(edits, unsafeImport(f, src, off))
	slices.SortFunc(edits, func(a, b srcEdit) int { return b.start - a.start })
	out := slices.Clone(src)
	for _, e := range edits {
		out = slices.Concat(out[:e.start], []byte(e.text), out[e.end:])
	}
	b, err := format.Source(out)
	if err != nil {
		return nil, fmt.Errorf("%s: gofmt: %w", name, err)
	}
	return b, nil
}

// unsafeImport adds `_ "unsafe"` to the imports of f, as TinyGo honors
// //go:section only with unsafe imported.
func unsafeImport(f *ast.File, src []byte, off func(token.Pos) int) srcEdit {
	const spec = `_ "unsafe"`
	var last *ast.GenDecl
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			last = gd
		}
	}
	switch {
	case last == nil:
		p := off(f.Name.End())
		return srcEdit{p, p, "\n\nimport " + spec}
	case last.Rparen.IsValid():
		p := off(last.Rparen)
		return srcEdit{p, p, "\t" + spec + "\n"}
	default:
		s, e := off(last.Specs[0].Pos()), off(last.End())
		return srcEdit{s, e, "(\n\t" + string(src[s:e]) + "\n\t" + spec + "\n)"}
	}
}
