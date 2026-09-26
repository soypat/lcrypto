// Package testenv is the subset of Go's internal/testenv used by the test
// support packages lcryptogen ports from the standard library, such as
// internal/lcryptotest/cryptotest. lcryptogen maps imports of internal/testenv,
// internal/race, internal/msan and internal/asan here.
package testenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// SanitizersEnabled reports whether the race detector, msan or asan is enabled.
const SanitizersEnabled = raceEnabled || msanEnabled || asanEnabled

// MustHaveExternalNetwork skips t in -short mode, when GOPROXY or GOFLAGS rule
// out downloads, when LCRYPTO_OFFLINE is set, or under TinyGo, whose os/exec
// cannot run the go command that downloads.
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	switch {
	case TinyGo:
		t.Skip("skipping test that needs the network: TinyGo cannot run the go command")
	case testing.Short():
		t.Skip("skipping test that needs the network in -short mode")
	case os.Getenv("LCRYPTO_OFFLINE") != "":
		t.Skip("skipping test that needs the network: LCRYPTO_OFFLINE is set")
	case os.Getenv("GOPROXY") == "off" || strings.Contains(os.Getenv("GOFLAGS"), "-mod=vendor"):
		t.Skip("skipping test that needs the network: downloads are disabled")
	}
}

// GoToolPath returns the path of the go command, preferring the one of the
// running toolchain.
func GoToolPath(t testing.TB) string {
	t.Helper()
	if runtime.Compiler == "gc" {
		p := filepath.Join(runtime.GOROOT(), "bin", "go")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("skipping test: go command not found")
	}
	return p
}

// Command is exec.Command.
func Command(t testing.TB, name string, args ...string) *exec.Cmd {
	t.Helper()
	return exec.Command(name, args...)
}

// CleanCmdEnv drops GODEBUG from the environment of cmd, which the test binary
// may set for itself.
func CleanCmdEnv(cmd *exec.Cmd) *exec.Cmd {
	env := cmd.Environ()
	cmd.Env = env[:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

// SkipIfTinyGo skips t under TinyGo, saying why the test cannot run there.
func SkipIfTinyGo(t testing.TB, why string) {
	t.Helper()
	if TinyGo {
		t.Skip("skipping under TinyGo: " + why)
	}
}

// SkipIfShortAndSlow skips t in -short mode on architectures slow to run it.
func SkipIfShortAndSlow(t testing.TB) {
	t.Helper()
	switch runtime.GOARCH {
	case "arm", "mips", "mipsle", "mips64", "mips64le", "wasm":
		if testing.Short() {
			t.Skipf("skipping test in -short mode on %s", runtime.GOARCH)
		}
	}
}

// SkipIfOptimizationOff skips t when built with -gcflags=-N, where escape
// analysis does not keep values on the stack.
func SkipIfOptimizationOff(t testing.TB) {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range bi.Settings {
		if s.Key == "-gcflags" && strings.Contains(s.Value, "-N") {
			t.Skip("skipping test with optimization disabled")
		}
	}
}
