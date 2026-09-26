package sha3

import (
	"encoding/hex"
	"hash"
	"io"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

// TestCSHAKEAccumulated is crypto/sha3's: cSHAKE outputs over 40k customization
// strings and input lengths below, at and above the rate, accumulated into one
// hash cross-checked by the standard library against pycryptodome and noble.
func TestCSHAKEAccumulated(t *testing.T) {
	t.Run("cSHAKE128", func(t *testing.T) {
		testCSHAKEAccumulated(t, NewCShake128, (1600-256)/8,
			"bb14f8657c6ec5403d0b0e2ef3d3393497e9d3b1a9a9e8e6c81dbaa5fd809252")
	})
	t.Run("cSHAKE256", func(t *testing.T) {
		testCSHAKEAccumulated(t, NewCShake256, (1600-512)/8,
			"0baaf9250c6e25f0c14ea5c7f9bfde54c8a922c8276437db28f3895bdf6eeeef")
	})
}

func testCSHAKEAccumulated(t *testing.T, newCSHAKE func(N, S []byte) *SHAKE, rate int64, exp string) {
	rnd := newCSHAKE(nil, nil)
	acc := newCSHAKE(nil, nil)
	for n := 0; n < 200; n++ {
		N := make([]byte, n)
		rnd.Read(N)
		for s := 0; s < 200; s++ {
			S := make([]byte, s)
			rnd.Read(S)

			c := newCSHAKE(N, S)
			io.CopyN(c, rnd, 100 /* < rate */)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, rate)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, 200 /* > rate */)
			io.CopyN(acc, c, 200)
		}
	}
	out := make([]byte, 32)
	acc.Read(out)
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestHash(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() *Digest
	}{
		{"SHA3-224", New224}, {"SHA3-256", New256}, {"SHA3-384", New384}, {"SHA3-512", New512},
		{"Keccak-256", NewLegacyKeccak256}, {"Keccak-512", NewLegacyKeccak512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cryptotest.TestHash(t, func() hash.Hash { return tc.new() })
		})
	}
}
