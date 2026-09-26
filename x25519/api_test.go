package x25519

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
	lcryptotest.WycheproofX25519(t, func() lcrypto.Exchanger { return new(Exchanger) })
}
