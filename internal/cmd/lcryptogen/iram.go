package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
)

// iramTag selects targets whose linker script runs .iram* sections from on-chip RAM.
const iramTag = "tinygo && esp"

// splitIRAM moves the functions of spec.IRAM out of the generated file name into
// name_iram.go, which places them in IRAM, and name_noiram.go, which keeps them
// as they are. It returns the files to write and counts matches in hits.
func splitIRAM(spec *pkgSpec, name string, src []byte, hits map[string]int) (map[string][]byte, error) {
	files := map[string][]byte{name: src}
	if len(spec.IRAM) == 0 || strings.HasSuffix(name, "_test.go") {
		return files, nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	off := func(p token.Pos) int { return fset.Position(p).Offset }
	var moved [][2]int
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !slices.Contains(spec.IRAM, funcName(fd)) {
			continue
		}
		hits[funcName(fd)]++
		start := fd.Pos()
		if fd.Doc != nil {
			start = fd.Doc.Pos()
		}
		moved = append(moved, [2]int{off(start), off(fd.End())})
	}
	if len(moved) == 0 {
		return files, nil
	}
	var rest, plain, iram bytes.Buffer
	last := 0
	for _, m := range moved {
		rest.Write(src[last:m[0]])
		last = m[1]
		fn := src[m[0]:m[1]]
		plain.Write(fn)
		plain.WriteString("\n\n")
		doc, body := splitDoc(fn)
		iram.Write(doc)
		if len(doc) > 0 {
			iram.WriteString("//\n")
		}
		iram.WriteString("//go:section .iram." + spec.Dst + "\n//go:noinline\n")
		iram.Write(body)
		iram.WriteString("\n\n")
	}
	rest.Write(src[last:])

	hdr := src[:bytes.Index(src, []byte("\n\n"))+2]
	imps := importNames(f)
	b, err := dropUnusedImports(rest.Bytes(), imps)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	files[name] = b
	base := strings.TrimSuffix(name, ".go")
	for _, v := range []struct {
		suffix, tag string
		body        []byte
		unsafe      bool
	}{
		{"_iram.go", iramTag, iram.Bytes(), true},
		{"_noiram.go", "!(" + iramTag + ")", plain.Bytes(), false},
	} {
		var out bytes.Buffer
		out.Write(hdr)
		out.WriteString("//go:build " + v.tag + "\n\npackage " + f.Name.Name + "\n\n")
		var use []string
		for local, path := range imps {
			if bytes.Contains(v.body, []byte(local+".")) {
				use = append(use, strconv.Quote(path))
			}
		}
		if v.unsafe {
			use = append(use, `_ "unsafe"`) // TinyGo honors //go:section only with unsafe imported.
		}
		slices.Sort(use)
		if len(use) > 0 {
			out.WriteString("import (\n\t" + strings.Join(use, "\n\t") + "\n)\n\n")
		}
		out.Write(v.body)
		b, err := format.Source(out.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s%s: gofmt: %w", base, v.suffix, err)
		}
		files[base+v.suffix] = b
	}
	return files, nil
}

// splitDoc separates the leading comment lines of fn from the declaration.
func splitDoc(fn []byte) (doc, body []byte) {
	i := 0
	for bytes.HasPrefix(fn[i:], []byte("//")) {
		i += bytes.IndexByte(fn[i:], '\n') + 1
	}
	return fn[:i], fn[i:]
}

// importNames maps the local name of each import of f to its path.
func importNames(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, s := range f.Imports {
		p, _ := strconv.Unquote(s.Path.Value)
		local := p[strings.LastIndex(p, "/")+1:]
		if s.Name != nil {
			local = s.Name.Name
		}
		m[local] = p
	}
	return m
}

// dropUnusedImports removes imports of src that its code no longer references.
func dropUnusedImports(src []byte, imps map[string]string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var kill [][2]int
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		code := src[fset.Position(gd.End()).Offset:]
		for _, s := range gd.Specs {
			is := s.(*ast.ImportSpec)
			p, _ := strconv.Unquote(is.Path.Value)
			for local, path := range imps {
				if path == p && local != "_" && !bytes.Contains(code, []byte(local+".")) {
					kill = append(kill, [2]int{fset.Position(is.Pos()).Offset, fset.Position(is.End()).Offset})
				}
			}
		}
	}
	for i := len(kill) - 1; i >= 0; i-- {
		src = append(src[:kill[i][0]:kill[i][0]], src[kill[i][1]:]...)
	}
	return format.Source(bytes.ReplaceAll(src, []byte("import ()\n"), nil))
}
