// Package aesgcm implements AES-GCM of the TLS 1.3 cipher suites
// TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 as an [lcrypto.AEADCipher].
//
// The implementation is the Go standard library's generic (pure Go) AES-GCM,
// ported by lcryptogen. It is not constant time on platforms where the
// standard library would use assembly instead.
package aesgcm

import (
	"errors"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/std/gcm"
)

var _ lcrypto.AEADCipher = (*Cipher)(nil)

const (
	NonceSize = 12 // AES-GCM nonce length of TLS 1.3, RFC 8446 5.3.
	Overhead  = 16 // AES-GCM tag length.
)

var (
	errUnkeyed = errors.New("aesgcm: cipher used before Rekey")
	errKeySize = errors.New("aesgcm: key must be 16 or 32 bytes")
)

// Cipher is AES-GCM with a 12 byte nonce and 16 byte tag. Its zero value is
// unkeyed; [Cipher.Rekey] installs a key without allocating. Cipher is not safe
// for concurrent use.
type Cipher struct {
	g     gcm.GCM
	keyed bool
}

// NonceSize returns [NonceSize]. It is valid on an unkeyed Cipher.
func (c *Cipher) NonceSize() int { return NonceSize }

// Overhead returns [Overhead]. It is valid on an unkeyed Cipher.
func (c *Cipher) Overhead() int { return Overhead }

// Seal implements cipher.AEAD. It panics if c is unkeyed, as cipher.AEAD panics on misuse.
func (c *Cipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if !c.keyed {
		panic("aesgcm: Seal before Rekey")
	}
	return c.g.Seal(dst, nonce, plaintext, additionalData)
}

// Open implements cipher.AEAD.
func (c *Cipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if !c.keyed {
		return nil, errUnkeyed
	}
	return c.g.Open(dst, nonce, ciphertext, additionalData)
}

// Rekey installs a 16 byte (AES-128) or 32 byte (AES-256) key. On error c is left unkeyed.
func (c *Cipher) Rekey(key []byte) error {
	c.Zeroize()
	if len(key) != 16 && len(key) != 32 {
		return errKeySize
	}
	if err := c.g.Rekey(key); err != nil {
		return err
	}
	c.keyed = true
	return nil
}

// Zeroize wipes the key schedule, leaving c unkeyed.
func (c *Cipher) Zeroize() {
	c.g.Zeroize()
	c.keyed = false
}
