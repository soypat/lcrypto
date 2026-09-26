// Package quick runs testing/quick property checks where TinyGo's reflect,
// lacking function types, cannot run quick.Check: CheckN takes a function of
// N arguments with their types known at compile time. With the gc toolchain it
// is testing/quick's Check. lcryptogen maps ported tests' testing/quick
// imports here, rewriting quick.Check to CheckN by the checked function's
// arity.
package quick

import (
	"math/rand"
	"reflect"
	"testing/quick"
	"time"

	"github.com/soypat/lcrypto/internal/lcryptotest/testenv"
)

type (
	Config     = quick.Config
	CheckError = quick.CheckError
	Generator  = quick.Generator
)

// Check1 is quick.Check of a function of one argument.
func Check1[A any](f func(A) bool, config *Config) error {
	if !testenv.TinyGo {
		return quick.Check(f, config)
	}
	return check(config, func(r *rand.Rand) (bool, []any) {
		a := value[A](r)
		return f(a), []any{a}
	})
}

// Check2 is quick.Check of a function of two arguments.
func Check2[A, B any](f func(A, B) bool, config *Config) error {
	if !testenv.TinyGo {
		return quick.Check(f, config)
	}
	return check(config, func(r *rand.Rand) (bool, []any) {
		a, b := value[A](r), value[B](r)
		return f(a, b), []any{a, b}
	})
}

// Check3 is quick.Check of a function of three arguments.
func Check3[A, B, C any](f func(A, B, C) bool, config *Config) error {
	if !testenv.TinyGo {
		return quick.Check(f, config)
	}
	return check(config, func(r *rand.Rand) (bool, []any) {
		a, b, c := value[A](r), value[B](r), value[C](r)
		return f(a, b, c), []any{a, b, c}
	})
}

// check calls run as many times as quick.Check would, with the same random
// source defaults.
func check(config *Config, run func(*rand.Rand) (bool, []any)) error {
	if config == nil {
		config = new(Config)
	}
	r := config.Rand
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	n := config.MaxCount
	if n == 0 {
		n = 100
		if config.MaxCountScale != 0 {
			n = int(float64(n) * config.MaxCountScale)
		}
	}
	for i := 0; i < n; i++ {
		if ok, in := run(r); !ok {
			return &CheckError{Count: i + 1, In: in}
		}
	}
	return nil
}

// value is quick.Value of type T: its Generate method if it has one.
func value[T any](r *rand.Rand) T {
	var zero T
	v, ok := quick.Value(reflect.TypeOf(zero), r)
	if !ok {
		panic("quick: cannot generate values of type " + reflect.TypeOf(zero).String())
	}
	return v.Interface().(T)
}
