package main

import (
	"encoding/json"
	"errors"
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
	dirs := func(src string) (from, to string) {
		p := src[strings.IndexByte(src, ':')+1:]
		if strings.HasPrefix(src, "go:") {
			return filepath.Join(goroot, "src", p), filepath.Join(root, "local/_go", p)
		}
		return filepath.Join(mod.Dir, p), filepath.Join(root, "local/_x/crypto", p)
	}
	for _, spec := range packages {
		from, to := dirs(spec.Src)
		if err := clearFiles(to); err != nil {
			return err
		}
		if err := copyPkg(from, to); err != nil {
			return err
		}
	}
	for _, vs := range vectorSuites {
		if vs.Src != "" {
			from, to := dirs(vs.Src)
			if err := os.RemoveAll(to); err != nil {
				return err
			}
			if err := copyTree(from, to); err != nil {
				return err
			}
			continue
		}
		if err := fetchVectors(root, vs); err != nil {
			return err
		}
		if vs.Pin != "" {
			from, to := dirs(vs.Pin)
			if err := copyFile(from, to); err != nil {
				return err
			}
		}
	}
	return nil
}

// clearFiles removes the regular files of package directory dir and its
// testdata, so files of other versions do not become inputs. Subdirectories
// are other packages and are kept.
func clearFiles(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() && e.Name() == "testdata" {
			err = os.RemoveAll(filepath.Join(dir, e.Name()))
		} else if e.Type().IsRegular() {
			err = os.Remove(filepath.Join(dir, e.Name()))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// copyPkg copies the regular files of one package directory and its testdata tree.
func copyPkg(from, to string) error {
	ents, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() && e.Name() == "testdata" {
			err = copyTree(filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
		} else if e.Type().IsRegular() {
			err = copyFile(filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies the regular files of a directory tree.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		return copyFile(p, filepath.Join(to, rel))
	})
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

// fetchVectors downloads the module of vs and copies its files into local/_vectors.
func fetchVectors(root string, vs vectorSuite) error {
	cmd := exec.Command("go", "mod", "download", "-json", vs.Module+"@"+vs.Version)
	cmd.Dir = os.TempDir() // Outside the module: do not touch go.mod.
	b, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("downloading %s: %w", vs.Module, err)
	}
	var mod struct{ Dir string }
	if err := json.Unmarshal(b, &mod); err != nil {
		return err
	}
	to := filepath.Join(root, vectorsDir, vs.Dir)
	if err := os.RemoveAll(to); err != nil {
		return err
	}
	for _, f := range vs.Files {
		if err := copyFile(filepath.Join(mod.Dir, f), filepath.Join(to, f)); err != nil {
			return err
		}
	}
	return nil
}
