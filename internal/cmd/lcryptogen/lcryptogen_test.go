package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/testenv"
)

func root(t *testing.T) string {
	t.Helper()
	r, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, "local/_go")); err != nil {
		t.Skip("inputs missing; run `go run ./internal/cmd/lcryptogen fetch`")
	}
	return r
}

// TestUpToDate checks generation is deterministic and matches both the manifest
// and the checked-in internal/std tree.
func TestUpToDate(t *testing.T) {
	testenv.SkipIfTinyGo(t, "lcryptogen type checks with the host toolchain")
	r := root(t)
	out, inputs, err := generate(r)
	if err != nil {
		t.Fatal(err)
	}
	out2, _, err := generate(r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range out {
		if !bytes.Equal(v, out2[k]) {
			t.Errorf("%s: generation not deterministic", k)
		}
	}
	manifest, _ := os.ReadFile(filepath.Join(r, "internal/cmd/lcryptogen/manifest.txt"))
	if !bytes.Equal(manifest, renderManifest(inputs)) {
		t.Error("manifest.txt does not match inputs")
	}
	for k, v := range out {
		disk, err := os.ReadFile(filepath.Join(r, k))
		if err != nil || !bytes.Equal(disk, v) {
			t.Errorf("%s: stale, run go generate", k)
		}
	}
	for _, dir := range []string{stdDir, kitDir} {
		filepath.WalkDir(filepath.Join(r, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(r, p)
			b, _ := os.ReadFile(p)
			if _, ok := out[filepath.ToSlash(rel)]; !ok && bytes.HasPrefix(b, []byte(headerPrefix)) {
				t.Errorf("%s: stale generated file", rel)
			}
			return nil
		})
	}
}

// TestTinyGoAllocs builds the smoke programs in testdata for a microcontroller and
// fails on any heap allocation site in lcrypto except sliceForAppend growing a
// short dst, which callers avoid by passing enough capacity. ML-KEM is built with
// the 16 KiB stack it documents; everything else with the target default.
func TestTinyGoAllocs(t *testing.T) {
	t.Run("classical", func(t *testing.T) { tinygoAllocs(t, "picosmoke") })
	t.Run("pq", func(t *testing.T) { tinygoAllocs(t, "picosmokepq", "-stack-size=16KB") })
}

func tinygoAllocs(t *testing.T, prog string, flags ...string) {
	testenv.SkipIfTinyGo(t, "os/exec cannot set a working directory")
	if testing.Short() {
		t.Skip("slow")
	}
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("tinygo not installed")
	}
	r, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"build", "-o", filepath.Join(t.TempDir(), "smoke.elf"), "-target=pico", "-print-allocs=" + modulePath}, flags...)
	cmd := exec.Command("tinygo", append(args, "./internal/cmd/lcryptogen/testdata/"+prog)...)
	cmd.Dir = r
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" && !(strings.Contains(line, "size is not constant") && atSliceForAppend(line)) {
			t.Error(strings.TrimPrefix(line, r+"/"))
		}
	}
}

// atSliceForAppend reports whether the "file:line:col: msg" location is sliceForAppend's make.
func atSliceForAppend(line string) bool {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	src, err := os.ReadFile(parts[0])
	if err != nil {
		return false
	}
	lines := strings.Split(string(src), "\n")
	return n <= len(lines) && strings.TrimSpace(lines[n-1]) == "head = make([]byte, total)"
}
