//go:build !lcrypto_noed25519

package x509

import "github.com/soypat/lcrypto/ed25519"

type (
	ed25519Verifier = ed25519.Verifier
	ed25519Signer   = ed25519.Signer
)
