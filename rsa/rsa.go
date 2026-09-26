// Package rsa verifies RSA signatures as used by TLS 1.3 signature schemes
// rsa_pss_rsae_* and rsa_pkcs1_* and by X.509 certificates.
//
// Verification is the Go standard library's, ported by lcryptogen, with numbers
// held in fixed arrays: moduli of 1024 to 4096 bits are supported and nothing is
// heap allocated. A Verifier holds about 8 KiB of numbers and buffers.
package rsa

import (
	"errors"
	"hash"

	"github.com/soypat/lcrypto/internal/std/rsa"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/sha512"
)

// Hash identifies the digest a signature was made over.
type Hash uint8

const (
	SHA256 Hash = iota + 1
	SHA384
	SHA512
)

const (
	MinBits = rsa.MinBits // Smallest modulus accepted, as crypto/rsa by default.
	MaxBits = 4096        // Largest modulus supported.
)

// ErrVerification is returned for signatures that do not verify.
var ErrVerification = rsa.ErrVerification

var errHash = errors.New("rsa: unsupported hash")

// Verifier verifies RSA signatures. Its zero value is ready for use.
// It is not safe for concurrent use.
type Verifier struct {
	v    rsa.Verifier
	d256 sha256.Digest
	d512 sha512.Digest
}

// VerifyPKCS1v15 verifies the RSASSA-PKCS1-v1.5 signature sig of digest hashed by
// the public key with big-endian modulus n and exponent e.
func (v *Verifier) VerifyPKCS1v15(n []byte, e int, h Hash, hashed, sig []byte) error {
	name, _, err := v.hash(h)
	if err != nil {
		return err
	}
	return v.v.VerifyPKCS1v15(n, e, name, hashed, sig)
}

// VerifyPSS verifies the RSASSA-PSS signature sig of digest hashed by the public
// key (n, e). The salt must be as long as the digest, as RFC 8446 4.2.3 requires.
func (v *Verifier) VerifyPSS(n []byte, e int, h Hash, hashed, sig []byte) error {
	_, hh, err := v.hash(h)
	if err != nil {
		return err
	}
	return v.v.VerifyPSS(n, e, hh, hashed, sig, hh.Size())
}

func (v *Verifier) hash(h Hash) (string, hash.Hash, error) {
	switch h {
	case SHA256:
		v.d256.Init()
		return "SHA-256", &v.d256, nil
	case SHA384:
		v.d512.Init384()
		return "SHA-384", &v.d512, nil
	case SHA512:
		v.d512.Init()
		return "SHA-512", &v.d512, nil
	}
	return "", nil, errHash
}
