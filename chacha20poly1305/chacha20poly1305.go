// Package chacha20poly1305 implements ChaCha20-Poly1305 of RFC 8439, the AEAD of
// the TLS 1.3 cipher suite TLS_CHACHA20_POLY1305_SHA256, as an [lcrypto.AEADCipher].
//
// The implementation is golang.org/x/crypto's generic (pure Go) code, ported by lcryptogen.
package chacha20poly1305

import (
	"errors"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/std/chacha20poly1305"
)

var _ lcrypto.AEADCipher = (*Cipher)(nil)

const (
	KeySize   = chacha20poly1305.KeySize   // Key length.
	NonceSize = chacha20poly1305.NonceSize // Nonce length.
	Overhead  = chacha20poly1305.Overhead  // Poly1305 tag length.
)

var errUnkeyed = errors.New("chacha20poly1305: cipher used before Rekey")

// Cipher is ChaCha20-Poly1305. Its zero value is unkeyed; [Cipher.Rekey] installs
// a key without allocating. The per-record ChaCha20 stream, Poly1305 state and
// one-time key live inside Cipher, so it is not safe for concurrent use.
type Cipher struct {
	a     chacha20poly1305.AEAD
	keyed bool
}

// NonceSize returns [NonceSize]. It is valid on an unkeyed Cipher.
func (c *Cipher) NonceSize() int { return NonceSize }

// Overhead returns [Overhead]. It is valid on an unkeyed Cipher.
func (c *Cipher) Overhead() int { return Overhead }

// Seal implements cipher.AEAD. It panics if c is unkeyed, as cipher.AEAD panics on misuse.
func (c *Cipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if !c.keyed {
		panic("chacha20poly1305: Seal before Rekey")
	}
	return c.a.Seal(dst, nonce, plaintext, additionalData)
}

// Open implements cipher.AEAD.
func (c *Cipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if !c.keyed {
		return nil, errUnkeyed
	}
	return c.a.Open(dst, nonce, ciphertext, additionalData)
}

// Rekey installs a [KeySize] key. On error c is left unkeyed.
func (c *Cipher) Rekey(key []byte) error {
	c.keyed = false
	if err := c.a.Rekey(key); err != nil {
		return err
	}
	c.keyed = true
	return nil
}

// Zeroize wipes the key and per-record state, leaving c unkeyed.
func (c *Cipher) Zeroize() {
	c.a.Zeroize()
	c.keyed = false
}
