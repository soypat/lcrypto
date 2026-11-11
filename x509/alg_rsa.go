//go:build !lcrypto_norsa

package x509

import "github.com/soypat/lcrypto/rsa"

type rsaVerifier = rsa.Verifier
