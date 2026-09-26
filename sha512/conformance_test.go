package sha512

import (
	"hash"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestHash(t *testing.T) {
	t.Run("SHA-512", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash { return New() })
	})
	t.Run("SHA-384", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash { return New384() })
	})
}

func TestNoExtraMethods(t *testing.T) {
	var h hash.Hash = New()
	cryptotest.NoExtraMethods(t, &h, "Init", "Init384", "Zeroize")
}
