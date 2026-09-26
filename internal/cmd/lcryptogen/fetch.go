package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// fetch recreates the gitignored inputs local/_go and local/_x from the Go module
// cache, downloading the pinned toolchain and x/crypto module if needed.
func fetch(root string) error {
	cmd := exec.Command("go", "env", "GOROOT")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN="+goVersion)
	b, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("locating %s GOROOT: %w", goVersion, err)
	}
	goroot := strings.TrimSpace(string(b))
	cmd = exec.Command("go", "mod", "download", "-json", "golang.org/x/crypto@"+xcryptoVersion)
	cmd.Dir = os.TempDir() // Outside the module: do not touch go.mod.
	b, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("downloading x/crypto: %w", err)
	}
	var mod struct{ Dir string }
	if err := json.Unmarshal(b, &mod); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(goroot, "LICENSE"), filepath.Join(root, "local/_go/LICENSE")); err != nil {
		return err
	}
	for _, spec := range packages {
		var from, to string
		switch p := spec.Src[strings.IndexByte(spec.Src, ':')+1:]; {
		case strings.HasPrefix(spec.Src, "go:"):
			from, to = filepath.Join(goroot, "src", p), filepath.Join(root, "local/_go", p)
		default:
			from, to = filepath.Join(mod.Dir, p), filepath.Join(root, "local/_x/crypto", p)
		}
		if err := copyPkg(from, to); err != nil {
			return err
		}
	}
	return nil
}

// copyPkg copies the regular files of one package directory and its testdata.
func copyPkg(from, to string) error {
	ents, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() && e.Name() == "testdata" {
			if err := copyPkg(filepath.Join(from, "testdata"), filepath.Join(to, "testdata")); err != nil {
				return err
			}
		}
		if e.Type().IsRegular() {
			if err := copyFile(filepath.Join(from, e.Name()), filepath.Join(to, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	return os.WriteFile(to, b, fs.FileMode(0o644))
}
