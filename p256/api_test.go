package p256

import (
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestNoExtraMethods(t *testing.T) {
	var x lcrypto.Exchanger = new(Exchanger)
	cryptotest.NoExtraMethods(t, &x)
}

func TestWycheproof(t *testing.T) {
	lcryptotest.WycheproofECDH(t, "ecdh_secp256r1_ecpoint_test.json", 32, func() lcrypto.Exchanger { return new(Exchanger) })
}
