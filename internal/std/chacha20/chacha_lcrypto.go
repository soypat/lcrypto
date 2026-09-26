package chacha20

// Init keys s in place with a 32 byte key and 12 or 24 byte nonce. It is the
// allocation-free counterpart of [NewUnauthenticatedCipher]. On error s is zeroed.
func (s *Cipher) Init(key, nonce []byte) error {
	*s = Cipher{}
	_, err := newUnauthenticatedCipher(s, key, nonce)
	return err
}
