package gcm

import "github.com/soypat/lcrypto/internal/std/aes"

// Rekey installs an AES key with the TLS 1.3 parameters, 12 byte nonce and 16 byte
// tag, reusing g's memory. On error g is left zeroed.
func (g *GCM) Rekey(key []byte) error {
	g.Zeroize()
	if err := aes.InitBlock(&g.cipher, key); err != nil {
		return err
	}
	g.nonceSize = gcmStandardNonceSize
	g.tagSize = gcmTagSize
	initGCM(g)
	return nil
}

// Zeroize wipes the expanded key and all derived state.
func (g *GCM) Zeroize() { *g = GCM{} }
