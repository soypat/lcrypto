package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand/v2"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

func TestContract(t *testing.T) {
	for _, keyLen := range []int{16, 32} {
		lcryptotest.AEAD(t, new(Cipher), make([]byte, keyLen))
	}
}

func TestDifferential(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var c Cipher
	for i := range 500 {
		key := make([]byte, 16+16*(i%2))
		nonce := make([]byte, NonceSize)
		msg := make([]byte, rng.IntN(300))
		ad := make([]byte, rng.IntN(40))
		for _, b := range [][]byte{key, nonce, msg, ad} {
			for j := range b {
				b[j] = byte(rng.Uint32())
			}
		}
		block, _ := aes.NewCipher(key)
		want, _ := cipher.NewGCM(block)
		if err := c.Rekey(key); err != nil {
			t.Fatal(err)
		}
		sealed := c.Seal(nil, nonce, msg, ad)
		lcryptotest.Equal(t, "Seal", sealed, want.Seal(nil, nonce, msg, ad))
		opened, err := c.Open(nil, nonce, sealed, ad)
		if err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "Open", opened, msg)
	}
}

func BenchmarkSeal1K(b *testing.B) {
	var c Cipher
	c.Rekey(make([]byte, 16))
	nonce := make([]byte, NonceSize)
	buf := make([]byte, 1024, 1024+Overhead)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		c.Seal(buf[:0], nonce, buf, nil)
	}
}
