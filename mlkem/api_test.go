package mlkem

import (
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

func TestNoExtraMethods(t *testing.T) {
	var x lcrypto.Exchanger = new(Exchanger768)
	cryptotest.NoExtraMethods(t, &x)
}
