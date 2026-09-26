package mlkem

// InitDecapsulationKey768 derives dk in place from a 64 byte "d || z" seed,
// FIPS 203 ML-KEM.KeyGen_internal. It is the allocation-free [NewDecapsulationKey768].
func InitDecapsulationKey768(dk *DecapsulationKey768, seed []byte) error {
	_, err := newKeyFromSeed(dk, seed)
	return err
}

// ParseEncapsulationKey768 parses and checks an encapsulation key into ek. It is
// the allocation-free [NewEncapsulationKey768].
func ParseEncapsulationKey768(ek *EncapsulationKey768, encapsulationKey []byte) error {
	_, err := parseEK(ek, encapsulationKey)
	return err
}

// AppendEncapsulationKey appends the encoded encapsulation key of dk to b.
func (dk *DecapsulationKey768) AppendEncapsulationKey(b []byte) []byte {
	return dk.encapsulationKeyBytes(b)
}

func (dk *DecapsulationKey768) encapsulationKeyBytes(b []byte) []byte {
	for i := range dk.t {
		b = polyByteEncode(b, dk.t[i])
	}
	return append(b, dk.ρ[:]...)
}

// EncapsulateTo is FIPS 203 ML-KEM.Encaps_internal with caller supplied randomness m.
// It writes the ciphertext to cc and returns the shared key, which aliases scratch
// space in ek and is valid until the next use of ek.
func (ek *EncapsulationKey768) EncapsulateTo(cc *[CiphertextSize768]byte, m *[32]byte) (sharedKey []byte) {
	sharedKey, _ = kemEncaps(cc, ek, m)
	return sharedKey
}

// Zeroize wipes dk, scratch space included.
func (dk *DecapsulationKey768) Zeroize() { *dk = DecapsulationKey768{} }

// Zeroize wipes ek, scratch space included.
func (ek *EncapsulationKey768) Zeroize() { *ek = EncapsulationKey768{} }
