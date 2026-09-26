package nistec

import (
	"errors"
	"math/bits"

	"github.com/soypat/lcrypto/internal/std/byteorder"
)

// P256VerifyScratch is the working memory of [P256Verify].
type P256VerifyScratch struct {
	p1      P256Point
	scratch P256Scratch
	scalar  [32]byte
	rx      [32]byte
}

var (
	errSigRange  = errors.New("ecdsa: invalid signature: r or s out of range")
	errSigVerify = errors.New("ecdsa: signature did not verify")
	errEmptyHash = errors.New("ecdsa: hash cannot be empty")
)

// P256Verify checks the ECDSA signature (r, s) of hash by public key q, which it
// overwrites. It follows crypto/internal/fips140/ecdsa.verifyGeneric with the
// fixed size scalar arithmetic of this package in place of bigmod:
//
//	w = s⁻¹, u1 = e·w, u2 = r·w (mod n); valid if x(u1·G + u2·Q) ≡ r (mod n).
//
// r and s are big-endian without leading zeroes, as read from ASN.1.
func P256Verify(q *P256Point, hash, r, s []byte, sc *P256VerifyScratch) error {
	if len(hash) == 0 {
		return errEmptyHash
	}
	var rs, ss, e, w, u p256OrdElement
	if !p256OrdSetCanonical(&rs, r) || !p256OrdSetCanonical(&ss, s) {
		return errSigRange
	}
	// hashToNat: the leftmost bits of hash, reduced once. ord(G) is 256 bits
	// long, so no bit shift is needed.
	var eb [32]byte
	if len(hash) >= len(eb) {
		copy(eb[:], hash[:len(eb)])
	} else {
		copy(eb[len(eb)-len(hash):], hash)
	}
	e.SetBytes(eb[:])

	w = ss
	P256OrdInverse((*[4]uint64)(&w))

	scalar := &sc.scalar
	p256OrdMulPlain(&u, &e, &w) // u1
	p256OrdPutBytes(scalar, &u)
	if _, err := sc.p1.ScalarBaseMult(scalar[:]); err != nil {
		return err
	}
	p256OrdMulPlain(&u, &rs, &w) // u2
	p256OrdPutBytes(scalar, &u)
	if _, err := q.ScalarMultScratch(q, scalar[:], &sc.scratch); err != nil {
		return err
	}
	if _, err := sc.p1.Add(&sc.p1, q).BytesXTo(&sc.rx); err != nil {
		return err
	}
	var v p256OrdElement
	v.SetBytes(sc.rx[:]) // SetOverflowingBytes: x < p < 2n, one reduction suffices.
	if v != rs {
		return errSigVerify
	}
	return nil
}

// p256OrdSetCanonical sets s to the big-endian value b and reports whether it
// is in [1, n-1], like bigmod.Nat.SetBytes followed by the IsZero check.
func p256OrdSetCanonical(s *p256OrdElement, b []byte) bool {
	if len(b) > 32 {
		return false
	}
	var buf [32]byte
	copy(buf[32-len(b):], b)
	s[0] = byteorder.BEUint64(buf[24:])
	s[1] = byteorder.BEUint64(buf[16:])
	s[2] = byteorder.BEUint64(buf[8:])
	s[3] = byteorder.BEUint64(buf[:])
	_, borrow := bits.Sub64(s[0], 0xf3b9cac2fc632551, 0)
	_, borrow = bits.Sub64(s[1], 0xbce6faada7179e84, borrow)
	_, borrow = bits.Sub64(s[2], 0xffffffffffffffff, borrow)
	_, borrow = bits.Sub64(s[3], 0xffffffff00000000, borrow)
	return borrow == 1 && s[0]|s[1]|s[2]|s[3] != 0
}

// p256OrdMulPlain sets out = a·b mod n for a, b and out outside the Montgomery
// domain: Mont(a)·b·R⁻¹ = a·b.
func p256OrdMulPlain(out, a, b *p256OrdElement) {
	var am p256OrdMontElement
	p256OrdToMontgomery(&am, a)
	p256OrdMul((*p256OrdMontElement)(out), &am, (*p256OrdMontElement)(b))
}

func p256OrdPutBytes(out *[32]byte, s *p256OrdElement) {
	byteorder.BEPutUint64(out[24:], s[0])
	byteorder.BEPutUint64(out[16:], s[1])
	byteorder.BEPutUint64(out[8:], s[2])
	byteorder.BEPutUint64(out[:], s[3])
}
