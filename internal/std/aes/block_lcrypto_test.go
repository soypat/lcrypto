package aes

import (
	"crypto/cipher"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

// TestBlockSuite runs the standard library's cipher.Block conformance suite,
// as crypto/aes does, on the generic AES.
func TestBlockSuite(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		t.Run(map[int]string{16: "AES-128", 24: "AES-192", 32: "AES-256"}[keySize], func(t *testing.T) {
			cryptotest.TestBlock(t, keySize, func(key []byte) (cipher.Block, error) { return New(key) })
		})
	}
}
