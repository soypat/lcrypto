//go:build lcrypto_nop384

package x509

import "io"

type p384Verifier struct{}

func (*p384Verifier) VerifyASN1(pub, hash, sig []byte) error { return ErrUnsupported }

type p384Signer struct{}

func (*p384Signer) SetKey(d []byte) error      { return ErrUnsupported }
func (*p384Signer) PublicKey() ([]byte, error) { return nil, ErrUnsupported }
func (*p384Signer) Zeroize()                   {}

func (*p384Signer) Sign(sig, msg, digest []byte, rand io.Reader) (int, error) {
	return 0, ErrUnsupported
}
