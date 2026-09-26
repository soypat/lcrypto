package sha256

import (
	"hash"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestHash(t *testing.T) {
	t.Run("SHA-256", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash { return New() })
	})
	t.Run("SHA-224", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash { d := new(Digest); d.Init224(); return d })
	})
}

func TestNoExtraMethods(t *testing.T) {
	var h hash.Hash = New()
	cryptotest.NoExtraMethods(t, &h, "Init", "Init224", "Zeroize")
}
