// Package ecdsa verifies ECDSA signatures over NIST P-256 as used by TLS 1.3
// signature scheme ecdsa_secp256r1_sha256 (0x0403) and X.509 certificates.
//
// Verification is the Go standard library's algorithm on its generic (pure Go)
// P-256 implementation, ported by lcryptogen, with fixed size scalar arithmetic
// in place of math/big style bignums: it does not allocate.
package ecdsa

import (
	"errors"

	"github.com/soypat/lcrypto/internal/std/cryptobyte"
	"github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"
	"github.com/soypat/lcrypto/internal/std/nistec"
)

const (
	SchemeP256SHA256  = 0x0403 // RFC 8446 4.2.3 ecdsa_secp256r1_sha256.
	P256PublicKeySize = 65     // Uncompressed point: 0x04 || X || Y.
)

var (
	errPublicKey = errors.New("ecdsa: P-256 public key must be a 65 byte uncompressed point")
	errASN1      = errors.New("ecdsa: invalid ASN.1 signature")
)

// P256Verifier holds the working memory of P-256 signature verification, about
// 2 KiB. Its zero value is ready for use. It is not safe for concurrent use.
type P256Verifier struct {
	q       nistec.P256Point
	scratch nistec.P256VerifyScratch
}

// VerifyASN1 checks sig, an ASN.1 DER ECDSA-Sig-Value, over hash by the
// uncompressed public key pub. hash is the message digest; it is truncated to
// 256 bits if longer, as in FIPS 186-5.
func (v *P256Verifier) VerifyASN1(pub, hash, sig []byte) error {
	r, s, ok := parseSignature(sig)
	if !ok {
		return errASN1
	}
	return v.Verify(pub, hash, r, s)
}

// Verify checks the signature (r, s), big-endian integers, over hash by the
// uncompressed public key pub.
func (v *P256Verifier) Verify(pub, hash, r, s []byte) error {
	if len(pub) != P256PublicKeySize || pub[0] != 4 {
		return errPublicKey
	}
	if _, err := v.q.SetBytes(pub); err != nil {
		return err
	}
	return nistec.P256Verify(&v.q, hash, r, s, &v.scratch)
}

// parseSignature is crypto/ecdsa's: SEQUENCE { r INTEGER, s INTEGER }, nothing trailing.
func parseSignature(sig []byte) (r, s []byte, ok bool) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	ok = input.ReadASN1(&inner, asn1.SEQUENCE) &&
		input.Empty() &&
		inner.ReadASN1IntegerBytes(&r) &&
		inner.ReadASN1IntegerBytes(&s) &&
		inner.Empty()
	return r, s, ok
}
