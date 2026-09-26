// Package ed25519 signs and verifies Ed25519 (RFC 8032) signatures as used by
// TLS 1.3 signature scheme ed25519 (0x0807) and X.509 certificates.
//
// It is the Go standard library's crypto/internal/fips140/ed25519 and
// edwards25519, ported by lcryptogen without the precomputed base point tables:
// the window tables of a multiplication live in the Signer or Verifier, which
// are about 4 KiB each. Nothing is heap allocated.
package ed25519

import (
	"errors"

	"github.com/soypat/lcrypto/internal/std/ed25519"
)

const (
	Scheme        = 0x0807 // RFC 8446 4.2.3 ed25519.
	SeedSize      = 32     // Private key seed, RFC 8032's private key.
	PublicKeySize = 32
	SignatureSize = 64
)

var (
	errNoKey    = errors.New("ed25519: no private key set")
	errShortSig = errors.New("ed25519: signature buffer too short")
)

// Signer signs with an Ed25519 private key. Signatures are deterministic, as
// RFC 8032 specifies. The zero value has no key; Zeroize wipes it. A Signer is
// not safe for concurrent use.
type Signer struct {
	priv   ed25519.PrivateKey
	sig    [SignatureSize]byte
	hasKey bool
}

// SetSeed sets the private key from its 32 byte seed, as crypto/ed25519's
// NewKeyFromSeed.
func (s *Signer) SetSeed(seed []byte) error {
	s.Zeroize()
	if err := s.priv.SetSeed(seed); err != nil {
		s.Zeroize()
		return err
	}
	s.hasKey = true
	return nil
}

// PublicKey returns the public key. The result aliases s.
func (s *Signer) PublicKey() ([]byte, error) {
	if !s.hasKey {
		return nil, errNoKey
	}
	return s.priv.PublicKeyBytes()[:], nil
}

// Sign writes the signature of message into sig, at least SignatureSize long,
// as crypto/ed25519's Sign.
func (s *Signer) Sign(sig, message []byte) error {
	if !s.hasKey {
		return errNoKey
	}
	if len(sig) < SignatureSize {
		return errShortSig
	}
	s.priv.SignTo(&s.sig, message)
	copy(sig, s.sig[:])
	return nil
}

// Zeroize wipes the key and all state.
func (s *Signer) Zeroize() { *s = Signer{} }

// Verifier verifies Ed25519 signatures. Its zero value is ready for use. It is
// not safe for concurrent use.
type Verifier struct {
	pub ed25519.PublicKey
}

// Verify checks sig is pub's signature of message, as crypto/ed25519's Verify.
func (v *Verifier) Verify(pub, message, sig []byte) error {
	if err := v.pub.SetBytes(pub); err != nil {
		return err
	}
	return v.pub.Verify(message, sig)
}
