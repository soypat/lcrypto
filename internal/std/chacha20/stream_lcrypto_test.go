package chacha20

import (
	"crypto/cipher"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

// TestStreamSuite runs the standard library's cipher.Stream conformance suite
// on ChaCha20 and XChaCha20.
func TestStreamSuite(t *testing.T) {
	for _, nonceSize := range []int{NonceSize, NonceSizeX} {
		t.Run(map[int]string{NonceSize: "ChaCha20", NonceSizeX: "XChaCha20"}[nonceSize], func(t *testing.T) {
			cryptotest.TestStream(t, func() cipher.Stream {
				var s Cipher
				if err := s.Init(make([]byte, KeySize), make([]byte, nonceSize)); err != nil {
					t.Fatal(err)
				}
				return &s
			})
		})
	}
}
