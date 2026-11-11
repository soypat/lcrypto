//go:build lcrypto_norsa

package x509

import "github.com/soypat/lcrypto/rsa"

type rsaVerifier struct{}

func (*rsaVerifier) VerifyPKCS1v15(n []byte, e int, h rsa.Hash, hashed, sig []byte) error {
	return ErrUnsupported
}

func (*rsaVerifier) VerifyPSS(n []byte, e int, h rsa.Hash, hashed, sig []byte) error {
	return ErrUnsupported
}
