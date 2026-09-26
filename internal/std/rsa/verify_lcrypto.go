package rsa

import (
	"bytes"
	"errors"
	"hash"

	"github.com/soypat/lcrypto/internal/std/bigmod"
)

// MinBits is the smallest modulus accepted, crypto/rsa's default (GODEBUG rsa1024min=1).
const MinBits = 1024

var errKeyTooSmall = errors.New("crypto/rsa: 1024-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)")

// Verifier holds the working memory of RSA signature verification: the modulus,
// two numbers and the encoded message. Verify* follow crypto/internal/fips140/rsa's
// verifyPKCS1v15 and verifyPSS, keeping every buffer here instead of the heap.
type Verifier struct {
	n    bigmod.Modulus
	pub  PublicKey
	s, m bigmod.Nat
	em   [maxModulusBytes]byte
	sc   rsaScratch
}

// publicOp checks the key (N, e) and returns sig^e mod N as a k byte message, k
// the size of N. It mirrors verifyPKCS1v15 and verifyPSS up to the encoding check.
func (v *Verifier) publicOp(N []byte, e int, sig []byte) (em []byte, pub *PublicKey, err error) {
	if err := bigmod.InitModulus(&v.n, N); err != nil {
		return nil, nil, err
	}
	pub = &v.pub // Fields set one by one: see lcryptogen's zeroThenAssign.
	pub.N, pub.E = &v.n, e
	if _, err := checkPublicKey(pub); err != nil {
		return nil, nil, err
	}
	if pub.N.BitLen() < MinBits {
		return nil, nil, errKeyTooSmall
	}
	// RFC 8017 Section 8.2.2: If the length of the signature S is not k
	// octets (where k is the length in octets of the RSA modulus n), output
	// "invalid signature" and stop.
	k := pub.Size()
	if len(sig) != k {
		return nil, nil, ErrVerification
	}
	if _, err := v.s.SetBytes(sig, &v.n); err != nil {
		return nil, nil, ErrVerification
	}
	v.m.ExpShortVarTime(&v.s, uint(e), &v.n)
	em = v.em[:k]
	v.m.FillBytes(em, &v.n)
	return em, pub, nil
}

// VerifyPKCS1v15 verifies an RSASSA-PKCS1-v1.5 signature by public key (N, e).
// hashName is as for crypto/internal/fips140/rsa, i.e. "SHA-256".
func (v *Verifier) VerifyPKCS1v15(N []byte, e int, hashName string, hashed, sig []byte) error {
	em, pub, err := v.publicOp(N, e, sig)
	if err != nil {
		return err
	}
	expected, err := pkcs1v15ConstructEM(&v.sc, pub, hashName, hashed)
	if err != nil {
		return ErrVerification
	}
	if !bytes.Equal(em, expected) {
		return ErrVerification
	}
	return nil
}

// VerifyPSS verifies an RSASSA-PSS signature by public key (N, e) with salt
// length saltLength, or any salt length if saltLength is negative.
func (v *Verifier) VerifyPSS(N []byte, e int, h hash.Hash, digest, sig []byte, saltLength int) error {
	em, pub, err := v.publicOp(N, e, sig)
	if err != nil {
		return err
	}
	if saltLength < 0 {
		saltLength = pssSaltLengthAutodetect
	}
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	// Like in signPSSWithSalt, deal with mismatches between emLen and the size
	// of the modulus.
	for len(em) > emLen && len(em) > 0 {
		if em[0] != 0 {
			return ErrVerification
		}
		em = em[1:]
	}
	return emsaPSSVerify(&v.sc, digest, em, emBits, saltLength, h)
}
