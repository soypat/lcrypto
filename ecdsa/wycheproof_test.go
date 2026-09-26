package ecdsa

import (
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"fmt"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/wycheproof"
)

func TestWycheproof(t *testing.T) {
	for _, tc := range []struct {
		curve  string
		hashes []string
		new    func() verifier
	}{
		{"secp256r1", []string{"sha256", "sha512", "sha3_256", "sha3_512"}, func() verifier { return new(P256Verifier) }},
		{"secp384r1", []string{"sha256", "sha384", "sha512", "sha3_384", "sha3_512"}, func() verifier { return new(P384Verifier) }},
	} {
		v := tc.new()
		for _, h := range tc.hashes {
			file := fmt.Sprintf("ecdsa_%s_%s_test.json", tc.curve, h)
			var testdata wycheproof.EcdsaVerifySchemaV1Json
			wycheproof.LoadVectorFile(t, file, &testdata)
			for _, tg := range testdata.TestGroups {
				pub := wycheproof.MustDecodeHex(tg.PublicKey.Uncompressed)
				hash := wycheproof.ParseHash(tg.Sha)
				for _, tv := range tg.Tests {
					t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
						h := hash.New()
						h.Write(wycheproof.MustDecodeHex(tv.Msg))
						got := v.VerifyASN1(pub, h.Sum(nil), wycheproof.MustDecodeHex(tv.Sig)) == nil
						if want := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil); got != want {
							t.Errorf("VerifyASN1 wanted success: %t", want)
						}
					})
				}
			}
		}
	}
}
