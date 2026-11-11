//go:build lcrypto_noed25519

package x509

type ed25519Verifier struct{}

func (*ed25519Verifier) Verify(pub, message, sig []byte) error { return ErrUnsupported }

type ed25519Signer struct{}

func (*ed25519Signer) SetSeed(seed []byte) error      { return ErrUnsupported }
func (*ed25519Signer) PublicKey() ([]byte, error)     { return nil, ErrUnsupported }
func (*ed25519Signer) Sign(sig, message []byte) error { return ErrUnsupported }
func (*ed25519Signer) Zeroize()                       {}
