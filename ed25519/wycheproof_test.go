package ed25519

import (
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/wycheproof"
)

func TestWycheproof(t *testing.T) {
	const file = "ed25519_test.json"
	var testdata wycheproof.EddsaVerifySchemaV1Json
	wycheproof.LoadVectorFile(t, file, &testdata)
	var v Verifier
	for _, tg := range testdata.TestGroups {
		pub := wycheproof.MustDecodeHex(tg.PublicKey.Pk)
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				got := v.Verify(pub, wycheproof.MustDecodeHex(tv.Msg), wycheproof.MustDecodeHex(tv.Sig)) == nil
				if want := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil); got != want {
					t.Errorf("Verify wanted success: %t", want)
				}
			})
		}
	}
}
