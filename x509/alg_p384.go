//go:build !lcrypto_nop384

package x509

import (
	"io"

	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/sha512"
)

type p384Verifier = ecdsa.P384Verifier

// p384Signer signs ecdsa_secp384r1_sha384 with its own SHA-384 state.
type p384Signer struct {
	s ecdsa.P384Signer
	d sha512.Digest
}

func (s *p384Signer) SetKey(d []byte) error      { return s.s.SetKey(d) }
func (s *p384Signer) PublicKey() ([]byte, error) { return s.s.PublicKey() }

func (s *p384Signer) Sign(sig, msg, digest []byte, rand io.Reader) (int, error) {
	s.d.Init384()
	s.d.Write(msg)
	return s.s.SignASN1(sig, s.d.Sum(digest[:0]), rand)
}

func (s *p384Signer) Zeroize() {
	s.s.Zeroize()
	s.d = sha512.Digest{} // Zeroize panics on a never initialized SHA-512 Digest.
}
