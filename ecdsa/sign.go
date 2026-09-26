package ecdsa

import (
	"errors"
	"io"

	"github.com/soypat/lcrypto/internal/std/nistec"
)

const (
	P256SignatureMaxSize = 72  // Largest ASN.1 DER P-256 signature.
	P384SignatureMaxSize = 104 // Largest ASN.1 DER P-384 signature.
)

var errDetHash = errors.New("ecdsa: deterministic signing needs a SHA-256, SHA-384 or SHA-512 digest")

// P256Signer signs with a P-256 private key, as crypto/ecdsa does:
//
//   - With a rand Reader, signatures are hedged: the nonce comes from an
//     HMAC_DRBG seeded with entropy from rand, the key and the hash, so a weak
//     or failing entropy source does not leak the key.
//   - With a nil rand, signatures are deterministic per RFC 6979, which needs
//     no entropy source at all.
//
// Arithmetic on the key and nonce is constant time. The zero value has no key;
// Zeroize wipes it. A P256Signer is not safe for concurrent use.
type P256Signer struct {
	s    nistec.P256Signer
	r, v [32]byte
	pub  [P256PublicKeySize]byte
}

// SetKey sets the private key d, big-endian of at most 32 bytes, in [1, n-1].
func (s *P256Signer) SetKey(d []byte) error { return s.s.SetKey(d) }

// PublicKey returns the uncompressed public key of the private key set. The
// result aliases s and is valid until the next call.
func (s *P256Signer) PublicKey() ([]byte, error) { return s.s.PublicKeyTo(&s.pub) }

// SignASN1 writes the ASN.1 DER ECDSA-Sig-Value signature of hash into sig and
// returns its length. If sig is too short it writes nothing and returns the
// length needed with [io.ErrShortBuffer]. With a nil rand, hash must be a
// SHA-256, SHA-384 or SHA-512 digest, whose function RFC 6979 uses.
func (s *P256Signer) SignASN1(sig, hash []byte, rand io.Reader) (int, error) {
	det, err := detHash(hash, rand)
	if err != nil {
		return 0, err
	}
	if err := s.s.Sign(hash, rand, det, &s.r, &s.v); err != nil {
		return 0, err
	}
	return encodeSignature(sig, s.r[:], s.v[:])
}

// Zeroize wipes the key and all state.
func (s *P256Signer) Zeroize() { *s = P256Signer{} }

// P384Signer signs with a P-384 private key. See [P256Signer].
type P384Signer struct {
	s    nistec.P384Signer
	r, v [48]byte
	pub  [P384PublicKeySize]byte
}

// SetKey sets the private key d, big-endian of at most 48 bytes, in [1, n-1].
func (s *P384Signer) SetKey(d []byte) error { return s.s.SetKey(d) }

// PublicKey returns the uncompressed public key of the private key set. The
// result aliases s and is valid until the next call.
func (s *P384Signer) PublicKey() ([]byte, error) { return s.s.PublicKeyTo(&s.pub) }

// SignASN1 is [P256Signer.SignASN1] for P-384.
func (s *P384Signer) SignASN1(sig, hash []byte, rand io.Reader) (int, error) {
	det, err := detHash(hash, rand)
	if err != nil {
		return 0, err
	}
	if err := s.s.Sign(hash, rand, det, &s.r, &s.v); err != nil {
		return 0, err
	}
	return encodeSignature(sig, s.r[:], s.v[:])
}

// Zeroize wipes the key and all state.
func (s *P384Signer) Zeroize() { *s = P384Signer{} }

func detHash(hash []byte, rand io.Reader) (uint8, error) {
	if rand != nil {
		return 0, nil
	}
	switch len(hash) {
	case 32:
		return nistec.HashSHA256, nil
	case 48:
		return nistec.HashSHA384, nil
	case 64:
		return nistec.HashSHA512, nil
	}
	return 0, errDetHash
}

// encodeSignature writes SEQUENCE { r INTEGER, s INTEGER } from the fixed size
// big-endian r and s. Lengths stay below 128: short form throughout.
func encodeSignature(sig, r, s []byte) (int, error) {
	r, rpad := minimal(r)
	s, spad := minimal(s)
	lr, ls := len(r)+rpad, len(s)+spad
	n := 2 + 2 + lr + 2 + ls
	if len(sig) < n {
		return n, io.ErrShortBuffer
	}
	sig[0], sig[1] = 0x30, byte(n-2)
	i := 2
	i += putInteger(sig[i:], r, rpad)
	putInteger(sig[i:], s, spad)
	return n, nil
}

// minimal strips leading zeroes and reports whether a 0x00 must precede the
// result to keep it positive.
func minimal(b []byte) ([]byte, int) {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		return b, 1
	}
	return b, 0
}

func putInteger(dst, b []byte, pad int) int {
	dst[0], dst[1] = 0x02, byte(len(b)+pad)
	dst[2] = 0
	copy(dst[2+pad:], b)
	return 2 + pad + len(b)
}
