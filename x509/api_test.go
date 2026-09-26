package x509

import (
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestNoExtraMethods(t *testing.T) {
	var v lcrypto.Verifier = new(Verifier)
	cryptotest.NoExtraMethods(t, &v, "Configure", "VerifyChain", "VerifyChainAnyName")
	var c lcrypto.Credential = new(Credential)
	cryptotest.NoExtraMethods(t, &c, "Configure", "Zeroize")
}
