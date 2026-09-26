package lcryptotest

import (
	"bytes"
	"testing"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/lcryptotest/wycheproof"
)

// WycheproofAEAD runs the Wycheproof AEAD vectors of file, such as
// "aes_gcm_test.json", against ciphers from newCipher, as crypto/cipher's
// TestGCMWycheproof does. Vectors whose key Rekey rejects, i.e. AES-192, are
// skipped; a nonce of the wrong size must make Seal and Open panic. It needs
// the network to fetch the vectors and skips in -short mode.
func WycheproofAEAD(t *testing.T, file string, newCipher func() lcrypto.AEADCipher) {
	var testdata wycheproof.AeadTestSchemaV1Json
	wycheproof.LoadVectorFile(t, file, &testdata)
	var tested int
	for _, tg := range testdata.TestGroups {
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				aead := newCipher()
				if aead.Rekey(wycheproof.MustDecodeHex(tv.Key)) != nil {
					return
				}
				tested++
				iv := wycheproof.MustDecodeHex(tv.Iv)
				tag := wycheproof.MustDecodeHex(tv.Tag)
				ct := wycheproof.MustDecodeHex(tv.Ct)
				msg := wycheproof.MustDecodeHex(tv.Msg)
				aad := wycheproof.MustDecodeHex(tv.Aad)
				ctWithTag := append(ct, tag...)

				if len(iv) != aead.NonceSize() {
					wycheproof.MustPanic(t, "Seal", func() { aead.Seal(nil, iv, msg, aad) })
					wycheproof.MustPanic(t, "Open", func() { aead.Open(nil, iv, ctWithTag, aad) })
					return
				}

				genCT := aead.Seal(nil, iv, msg, aad)
				genMsg, err := aead.Open(nil, iv, genCT, aad)
				if err != nil {
					t.Errorf("failed to decrypt generated ciphertext: %s", err)
				}
				if !bytes.Equal(genMsg, msg) {
					t.Errorf("unexpected roundtripped plaintext: got %x, want %x", genMsg, msg)
				}

				msg2, err := aead.Open(nil, iv, ctWithTag, aad)
				wantPass := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil)
				if !wantPass && err == nil {
					t.Error("decryption succeeded when it should've failed")
				} else if wantPass {
					if err != nil {
						t.Fatalf("decryption failed: %s", err)
					}
					if !bytes.Equal(genCT, ctWithTag) {
						t.Errorf("generated ciphertext doesn't match expected: got %x, want %x", genCT, ctWithTag)
					}
					if !bytes.Equal(msg, msg2) {
						t.Errorf("decrypted ciphertext doesn't match expected: got %x, want %x", msg2, msg)
					}
				}
			})
		}
	}
	if tested == 0 {
		t.Errorf("%s: no vector had a key the cipher accepts", file)
	}
}

// WycheproofX25519 runs the Wycheproof X25519 vectors against exchangers from
// newX, as crypto/ecdh's TestX25519ECDHWycheproof does. See [WycheproofECDH].
func WycheproofX25519(t *testing.T, newX func() lcrypto.Exchanger) {
	const file = "x25519_test.json"
	flagsShouldPass := map[string]bool{
		"Twist":                  true,
		"SmallPublicKey":         false,
		"LowOrderPublic":         false,
		"ZeroSharedSecret":       false,
		"NonCanonicalPublic":     true,
		"SpecialPublicKey":       true,
		"EdgeCaseMultiplication": true,
		"EdgeCaseShared":         true,
		"Ktv":                    true,
	}
	var testdata wycheproof.XdhCompSchemaV1Json
	wycheproof.LoadVectorFile(t, file, &testdata)
	for _, tg := range testdata.TestGroups {
		if tg.Curve != "curve25519" {
			continue
		}
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				runECDHWycheproof(t, newX, 32, flagsShouldPass, tv.Result, tv.Flags, tv.Public, tv.Private, tv.Shared)
			})
		}
	}
}

// WycheproofECDH runs the Wycheproof ECDH vectors of file with public keys as
// encoded points, such as "ecdh_secp256r1_ecpoint_test.json", against
// exchangers from newX, as crypto/ecdh's TestSecpECDHWycheproof does.
//
// The vector's private key is the entropy of ServerSharedRekey, which must
// draw its scalar as the first keySize bytes of rand, and its public key the
// client share. Compressed points must be rejected.
func WycheproofECDH(t *testing.T, file string, keySize int, newX func() lcrypto.Exchanger) {
	flagsShouldPass := map[string]bool{
		"CompressedPoint":  false,
		"CompressedPublic": false,
	}
	var testdata wycheproof.EcdhEcpointTestSchemaV1Json
	wycheproof.LoadVectorFile(t, file, &testdata)
	for _, tg := range testdata.TestGroups {
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				runECDHWycheproof(t, newX, keySize, flagsShouldPass, tv.Result, tv.Flags, tv.Public, tv.Private, tv.Shared)
			})
		}
	}
}

func runECDHWycheproof(t *testing.T, newX func() lcrypto.Exchanger, keySize int, flagsShouldPass map[string]bool,
	result wycheproof.Result, flags []string, public, private, shared string) {
	t.Helper()
	shouldPass := wycheproof.ShouldPass(t, result, flags, flagsShouldPass)
	// Integers may carry a sign byte or lack leading zeros.
	priv := wycheproof.MustDecodeHex(private)
	for len(priv) > keySize && priv[0] == 0 {
		priv = priv[1:]
	}
	if len(priv) > keySize {
		t.Fatalf("private key of %d bytes", len(priv))
	}
	priv = append(make([]byte, keySize-len(priv)), priv...)

	x := newX()
	var share, got [2048]byte
	_, n, err := x.ServerSharedRekey(share[:], got[:], wycheproof.MustDecodeHex(public), bytes.NewReader(priv))
	if err != nil {
		if shouldPass {
			t.Errorf("ServerSharedRekey: %v", err)
		}
		return
	}
	want := wycheproof.MustDecodeHex(shared)
	if shouldPass {
		if !bytes.Equal(got[:n], want) {
			t.Errorf("shared secret %x, want %x", got[:n], want)
		}
	} else if result == "invalid" && bytes.Equal(got[:n], want) {
		t.Errorf("shared secret %x, want anything else", got[:n])
	}
}
