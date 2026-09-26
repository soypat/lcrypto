package x25519mlkem768

import (
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestNoExtraMethods(t *testing.T) {
	var x lcrypto.Exchanger = new(Exchanger)
	cryptotest.NoExtraMethods(t, &x)
}
