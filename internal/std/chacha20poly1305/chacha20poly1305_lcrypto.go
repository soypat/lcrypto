package chacha20poly1305

// AEAD is ChaCha20-Poly1305 of RFC 8439. Its zero value is unkeyed. Unlike the
// x/crypto original, Seal and Open use scratch space in the struct and so are not
// safe for concurrent use.
type AEAD = chacha20poly1305

// Rekey installs key. On error c is left zeroed.
func (c *chacha20poly1305) Rekey(key []byte) error {
	c.Zeroize()
	if len(key) != KeySize {
		return errBadKeyLength
	}
	copy(c.key[:], key)
	return nil
}

// Zeroize wipes the key, cipher stream, MAC state and one-time key.
func (c *chacha20poly1305) Zeroize() { *c = chacha20poly1305{} }
