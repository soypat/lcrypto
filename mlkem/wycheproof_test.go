package mlkem

import (
	"bytes"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/wycheproof"
)

// The Wycheproof tests drive the Exchanger with vector randomness: the key
// generation seed d || z and the encapsulation message m are read from rand.

func TestWycheproofKeyGen(t *testing.T) {
	const file = "mlkem_768_keygen_seed_test.json"
	var testdata wycheproof.MlkemKeygenSeedTestSchemaJson
	wycheproof.LoadVectorFile(t, file, &testdata)
	var x Exchanger768
	for _, tg := range testdata.TestGroups {
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				seed := wycheproof.MustDecodeHex(tv.Seed)
				var ek [ClientShareSize768]byte
				_, err := x.ClientGenerateRekey(ek[:], bytes.NewReader(seed))
				if valid := tv.Result == "valid" && len(seed) == seedSize; (err == nil) != valid {
					t.Fatalf("ClientGenerateRekey: %v, want success %t", err, valid)
				} else if err != nil {
					return
				}
				if !bytes.Equal(ek[:], wycheproof.MustDecodeHex(tv.Ek)) {
					t.Errorf("encapsulation key mismatch")
				}
			})
		}
	}
}

func TestWycheproofEncaps(t *testing.T) {
	const file = "mlkem_768_encaps_test.json"
	var testdata wycheproof.MlkemEncapsTestSchemaJson
	wycheproof.LoadVectorFile(t, file, &testdata)
	var x Exchanger768
	for _, tg := range testdata.TestGroups {
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				var c [ServerShareSize768]byte
				var k [SharedSize]byte
				_, _, err := x.ServerSharedRekey(c[:], k[:], wycheproof.MustDecodeHex(tv.Ek), bytes.NewReader(wycheproof.MustDecodeHex(tv.M)))
				if want := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil); (err == nil) != want {
					t.Fatalf("ServerSharedRekey: %v, want success %t", err, want)
				} else if err != nil {
					return
				}
				if !bytes.Equal(c[:], wycheproof.MustDecodeHex(tv.C)) {
					t.Errorf("ciphertext mismatch")
				}
				if !bytes.Equal(k[:], wycheproof.MustDecodeHex(tv.K)) {
					t.Errorf("shared key mismatch")
				}
			})
		}
	}
}

func TestWycheproofDecaps(t *testing.T) {
	const file = "mlkem_768_test.json"
	var testdata wycheproof.MlkemTestSchemaJson
	wycheproof.LoadVectorFile(t, file, &testdata)
	var x Exchanger768
	for _, tg := range testdata.TestGroups {
		for _, tv := range tg.Tests {
			t.Run(wycheproof.TestName(file, tv), func(t *testing.T) {
				shouldPass := wycheproof.ShouldPass(t, tv.Result, tv.Flags, nil)
				seed := wycheproof.MustDecodeHex(tv.Seed)
				var ek [ClientShareSize768]byte
				if len(seed) != seedSize {
					if shouldPass {
						t.Fatalf("valid vector with a %d byte seed", len(seed))
					}
					return
				}
				if _, err := x.ClientGenerateRekey(ek[:], bytes.NewReader(seed)); err != nil {
					t.Fatalf("ClientGenerateRekey: %v", err)
				}
				if tv.Ek != nil && !bytes.Equal(ek[:], wycheproof.MustDecodeHex(*tv.Ek)) {
					t.Errorf("encapsulation key mismatch")
				}
				var k [SharedSize]byte
				_, err := x.ClientShared(k[:], wycheproof.MustDecodeHex(tv.C))
				if (err == nil) != shouldPass {
					t.Fatalf("ClientShared: %v, want success %t", err, shouldPass)
				} else if err == nil && !bytes.Equal(k[:], wycheproof.MustDecodeHex(tv.K)) {
					t.Errorf("shared key mismatch: got %x, want %s", k, tv.K)
				}
			})
		}
	}
}
