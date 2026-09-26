// Package ecdsa verifies ECDSA signatures over NIST P-256 and P-384 as used by
// TLS 1.3 signature schemes ecdsa_secp256r1_sha256 (0x0403) and
// ecdsa_secp384r1_sha384 (0x0503) and by X.509 certificates.
//
// Verification is the Go standard library's algorithm on its generic (pure Go)
// curve implementations, ported by lcryptogen, with fixed size scalar arithmetic
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
	SchemeP384SHA384  = 0x0503 // RFC 8446 4.2.3 ecdsa_secp384r1_sha384.
	P256PublicKeySize = 65     // Uncompressed point: 0x04 || X || Y.
	P384PublicKeySize = 97     // Uncompressed point: 0x04 || X || Y.
)

var (
	errPublicKey    = errors.New("ecdsa: P-256 public key must be a 65 byte uncompressed point")
	errPublicKey384 = errors.New("ecdsa: P-384 public key must be a 97 byte uncompressed point")
	errASN1         = errors.New("ecdsa: invalid ASN.1 signature")
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

// P384Verifier holds the working memory of P-384 signature verification, about
// 3 KiB. Its zero value is ready for use. It is not safe for concurrent use.
type P384Verifier struct {
	q       nistec.P384Point
	scratch nistec.P384VerifyScratch
}

// VerifyASN1 checks sig, an ASN.1 DER ECDSA-Sig-Value, over hash by the
// uncompressed public key pub. hash is the message digest; it is truncated to
// 384 bits if longer, as in FIPS 186-5.
func (v *P384Verifier) VerifyASN1(pub, hash, sig []byte) error {
	r, s, ok := parseSignature(sig)
	if !ok {
		return errASN1
	}
	return v.Verify(pub, hash, r, s)
}

// Verify checks the signature (r, s), big-endian integers, over hash by the
// uncompressed public key pub.
func (v *P384Verifier) Verify(pub, hash, r, s []byte) error {
	if len(pub) != P384PublicKeySize || pub[0] != 4 {
		return errPublicKey384
	}
	if _, err := v.q.SetBytes(pub); err != nil {
		return err
	}
	return nistec.P384Verify(&v.q, hash, r, s, &v.scratch)
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
