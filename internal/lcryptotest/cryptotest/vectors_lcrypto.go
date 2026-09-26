package cryptotest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// Vectors returns file of the test vector suite that lcryptogen vendors,
// gzipped, into internal/lcryptotest/testdata/suite, such as
// Vectors(t, "wycheproof", "aes_gcm_test.json"), uncompressed. A file that is
// gzipped upstream keeps its name. It needs no network, so the
// suites run offline and under TinyGo. To vendor another file, add it to
// vectorSuites in internal/cmd/lcryptogen and run go generate.
func Vectors(t testing.TB, suite, file string) []byte {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	name := file
	if !strings.HasSuffix(name, ".gz") {
		name += ".gz"
	}
	return readGzip(t, filepath.Join(root, "internal", "lcryptotest", "testdata", suite, name))
}

// VectorFS returns the files of a suite that lcryptogen vendors as one archive,
// internal/lcryptotest/testdata/suite.tar.gz.
func VectorFS(t testing.TB, suite string) fstest.MapFS {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "internal", "lcryptotest", "testdata", suite+".tar.gz")
	tr := tar.NewReader(bytes.NewReader(readGzip(t, p)))
	fsys := fstest.MapFS{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fsys
		} else if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		fsys[h.Name] = &fstest.MapFile{Data: b, Mode: 0o444}
	}
}

func readGzip(t testing.TB, p string) []byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("not vendored, add it to vectorSuites in internal/cmd/lcryptogen: %v", err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return b
}

// moduleRoot finds the lcrypto module from the working directory, which go
// test and tinygo test set to the directory of the package under test.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.Contains(b, []byte("module github.com/soypat/lcrypto\n")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
