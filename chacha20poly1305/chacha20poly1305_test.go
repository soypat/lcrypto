package chacha20poly1305

import (
	"encoding/hex"
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestContract(t *testing.T) {
	lcryptotest.AEAD(t, new(Cipher), make([]byte, KeySize))
}

// RFC 8439 2.8.2 AEAD test vector.
func TestRFC8439(t *testing.T) {
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key := h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := h("070000004041424344454647")
	ad := h("50515253c0c1c2c3c4c5c6c7")
	msg := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := h("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
		"1ae10b594f09e26a7e902ecbd0600691")
	var c Cipher
	if err := c.Rekey(key); err != nil {
		t.Fatal(err)
	}
	sealed := c.Seal(nil, nonce, msg, ad)
	lcryptotest.Equal(t, "Seal", sealed, want)
	opened, err := c.Open(nil, nonce, sealed, ad)
	if err != nil {
		t.Fatal(err)
	}
	lcryptotest.Equal(t, "Open", opened, msg)
}

func BenchmarkSeal1K(b *testing.B) {
	var c Cipher
	c.Rekey(make([]byte, KeySize))
	nonce := make([]byte, NonceSize)
	buf := make([]byte, 1024, 1024+Overhead)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		c.Seal(buf[:0], nonce, buf, nil)
	}
}

func TestWycheproof(t *testing.T) {
	lcryptotest.WycheproofAEAD(t, "chacha20_poly1305_test.json", func() lcrypto.AEADCipher { return new(Cipher) })
}

func TestNoExtraMethods(t *testing.T) {
	var c lcrypto.AEADCipher = new(Cipher)
	cryptotest.NoExtraMethods(t, &c)
}
