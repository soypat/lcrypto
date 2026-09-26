//go:build tinygo

package testenv

// TinyGo reports whether the tests are built by TinyGo, whose reflect and
// os/exec lack what some tests need.
const TinyGo = true
