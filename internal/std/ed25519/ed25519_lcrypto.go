package ed25519

// Allocation-free entry points; upstream's return new keys and signatures.

// SetSeed sets priv from its 32 byte seed, as NewPrivateKeyFromSeed.
func (priv *PrivateKey) SetSeed(seed []byte) error {
	_, err := newPrivateKeyFromSeed(priv, seed)
	return err
}

// PublicKeyBytes returns the public key of priv.
func (priv *PrivateKey) PublicKeyBytes() *[publicKeySize]byte { return &priv.pub }

// SignTo writes the signature of message into sig, as Sign.
func (priv *PrivateKey) SignTo(sig *[signatureSize]byte, message []byte) {
	sign(sig[:], priv, message)
}

// SetBytes sets pub to the encoded public key b, as NewPublicKey.
func (pub *PublicKey) SetBytes(b []byte) error {
	_, err := newPublicKey(pub, b)
	return err
}

// Verify checks sig is pub's signature of message, as Verify.
func (pub *PublicKey) Verify(message, sig []byte) error { return verify(pub, message, sig) }
