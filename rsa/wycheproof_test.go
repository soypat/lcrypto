package rsa

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/wycheproof"
)

// wycheproofHashes are the Wycheproof digests Verifier supports.
var wycheproofHashes = map[string]Hash{"SHA-256": SHA256, "SHA-384": SHA384, "SHA-512": SHA512}

// wycheproofKey decodes a Wycheproof public key, reporting whether Verifier supports its size.
func wycheproofKey(t *testing.T, modulus, exponent string, keySize int) (n []byte, e int, ok bool) {
	if keySize < MinBits || keySize > MaxBits {
		return nil, 0, false
	}
	n = new(big.Int).SetBytes(wycheproof.MustDecodeHex(modulus)).Bytes()
	ebig := new(big.Int).SetBytes(wycheproof.MustDecodeHex(exponent))
	if !ebig.IsInt64() {
		t.Fatalf("exponent %s", exponent)
	}
	return n, int(ebig.Int64()), true
}

func digest(t *testing.T, sha, msg string) []byte {
	h := wycheproof.ParseHash(sha).New()
	h.Write(wycheproof.MustDecodeHex(msg))
	return h.Sum(nil)
}

func TestWycheproofPKCS1v15(t *testing.T) {
	flagsShouldPass := map[string]bool{
		"MissingNull": false, // Legacy encoding without the NULL parameters.
	}
	var v Verifier
	for _, bits := range []int{2048, 3072, 4096} {
		for _, sha := range []string{"sha256", "sha384", "sha512"} {
			file := fmt.Sprintf("rsa_signature_%d_%s_test.json", bits, sha)
			var testdata wycheproof.RsassaPkcs1VerifySchemaV1Json
			wycheproof.LoadVectorFile(t, file, &testdata)
			for _, tg := range testdata.TestGroups {
				h, ok := wycheproofHashes[tg.Sha]
				n, e, ok2 := wycheproofKey(t, tg.PublicKey.Modulus, tg.PublicKey.PublicExponent, tg.KeySize)
				if !ok || !ok2 {
					t.Fatalf("%s: unsupported group %s %d", file, tg.Sha, tg.KeySize)
				}
				for _, tv := range tg.Tests {
					t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
						err := v.VerifyPKCS1v15(n, e, h, digest(t, tg.Sha, tv.Msg), wycheproof.MustDecodeHex(tv.Sig))
						if want := wycheproof.ShouldPass(t, tv.Result, tv.Flags, flagsShouldPass); (err == nil) != want {
							t.Errorf("wanted success: %t err: %v", want, err)
						}
					})
				}
			}
		}
	}
}

// TestWycheproofPSS runs the groups Verifier supports: MGF1 with the message
// digest and a salt as long as the digest, as RFC 8446 4.2.3 requires.
func TestWycheproofPSS(t *testing.T) {
	var v Verifier
	var tested int
	for _, file := range []string{
		"rsa_pss_2048_sha256_mgf1_32_test.json",
		"rsa_pss_2048_sha384_mgf1_48_test.json",
		"rsa_pss_3072_sha256_mgf1_32_test.json",
		"rsa_pss_4096_sha256_mgf1_32_test.json",
		"rsa_pss_4096_sha384_mgf1_48_test.json",
		"rsa_pss_4096_sha512_mgf1_64_test.json",
		"rsa_pss_misc_test.json",
	} {
		var testdata wycheproof.RsassaPssVerifySchemaV1Json
		wycheproof.LoadVectorFile(t, file, &testdata)
		for _, tg := range testdata.TestGroups {
			h, ok := wycheproofHashes[tg.Sha]
			n, e, ok2 := wycheproofKey(t, tg.PublicKey.Modulus, tg.PublicKey.PublicExponent, tg.KeySize)
			if !ok || !ok2 || tg.Mgf != "MGF1" || tg.MgfSha != tg.Sha || tg.SLen != hashSize(h) {
				continue
			}
			for _, tv := range tg.Tests {
				tested++
				t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
					err := v.VerifyPSS(n, e, h, digest(t, tg.Sha, tv.Msg), wycheproof.MustDecodeHex(tv.Sig))
					if want := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil); (err == nil) != want {
						t.Errorf("wanted success: %t err: %v", want, err)
					}
				})
			}
		}
	}
	if tested == 0 {
		t.Error("no supported PSS vectors")
	}
}

func hashSize(h Hash) int {
	return map[Hash]int{SHA256: 32, SHA384: 48, SHA512: 64}[h]
}
