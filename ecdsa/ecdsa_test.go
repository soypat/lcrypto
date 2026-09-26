package ecdsa

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

var n = elliptic.P256().Params().N

func newKey(t testing.TB, seed byte) (*stdecdsa.PrivateKey, []byte) {
	k, err := stdecdsa.GenerateKey(elliptic.P256(), lcryptotest.NewRand(seed))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

// agree fails t if lcrypto and crypto/ecdsa disagree on (pub, hash, sig).
func agree(t testing.TB, v *P256Verifier, std *stdecdsa.PublicKey, pub, hash, sig []byte) bool {
	t.Helper()
	got := v.VerifyASN1(pub, hash, sig) == nil
	want := stdecdsa.VerifyASN1(std, hash, sig)
	if got != want {
		t.Fatalf("lcrypto %v, crypto/ecdsa %v\npub %x\nhash %x\nsig %x", got, want, pub, hash, sig)
	}
	return got
}

func TestDifferential(t *testing.T) {
	rand := lcryptotest.NewRand(6)
	v := new(P256Verifier)
	for i := range 40 {
		k, pub := newKey(t, byte(i))
		for _, hlen := range []int{1, 20, 32, 48, 64} {
			hash := make([]byte, hlen)
			rand.Read(hash)
			sig, err := stdecdsa.SignASN1(rand, k, hash)
			if err != nil {
				t.Fatal(err)
			}
			if !agree(t, v, &k.PublicKey, pub, hash, sig) {
				t.Fatal("valid signature rejected")
			}
			// Single bit flips anywhere must agree (and mostly fail).
			for _, b := range [][]byte{hash, sig} {
				j := int(rand.Uint64() % uint64(len(b)))
				b[j] ^= 1 << (rand.Uint64() % 8)
				agree(t, v, &k.PublicKey, pub, hash, sig)
				b[j] ^= 1 << (rand.Uint64() % 8)
			}
		}
	}
}

func TestEdgeCases(t *testing.T) {
	k, pub := newKey(t, 99)
	hash := sha256.Sum256([]byte("edge"))
	sig, _ := stdecdsa.SignASN1(lcryptotest.NewRand(1), k, hash[:])
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		t.Fatal(err)
	}
	der := func(r, s *big.Int) []byte {
		b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	one := big.NewInt(1)
	highS := new(big.Int).Sub(n, parsed.S)
	cases := map[string][]byte{
		"valid":          sig,
		"high s":         der(parsed.R, highS),
		"r zero":         der(big.NewInt(0), parsed.S),
		"s zero":         der(parsed.R, big.NewInt(0)),
		"r = n":          der(n, parsed.S),
		"s = n":          der(parsed.R, n),
		"r + n":          der(new(big.Int).Add(parsed.R, n), parsed.S),
		"r = n-1":        der(new(big.Int).Sub(n, one), parsed.S),
		"negative r":     der(new(big.Int).Neg(parsed.R), parsed.S),
		"r 2^256":        der(new(big.Int).Lsh(one, 256), parsed.S),
		"trailing":       append(append([]byte{}, sig...), 0),
		"empty":          nil,
		"non-minimal r":  append([]byte{0x30, sig[1] + 1, 0x02, sig[3] + 1, 0}, sig[4:]...),
		"truncated":      sig[:len(sig)-1],
		"sequence only":  {0x30, 0x00},
		"one integer":    {0x30, 0x03, 0x02, 0x01, 0x01},
		"indefinite len": {0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00},
	}
	v := new(P256Verifier)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { agree(t, v, &k.PublicKey, pub, hash[:], c) })
	}
	if v.VerifyASN1(pub, nil, sig) == nil {
		t.Error("accepted empty hash")
	}
	bad := append([]byte{}, pub...)
	bad[40] ^= 1
	if v.VerifyASN1(bad, hash[:], sig) == nil {
		t.Error("accepted public key off the curve")
	}
}

func TestAllocs(t *testing.T) {
	k, pub := newKey(t, 7)
	hash := sha256.Sum256([]byte("allocs"))
	sig, _ := stdecdsa.SignASN1(lcryptotest.NewRand(2), k, hash[:])
	v := new(P256Verifier)
	if allocs := testing.AllocsPerRun(5, func() {
		if err := v.VerifyASN1(pub, hash[:], sig); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("VerifyASN1 allocated %v times per run", allocs)
	}
}

func FuzzDifferential(f *testing.F) {
	k, pub := newKey(f, 8)
	hash := sha256.Sum256([]byte("fuzz"))
	sig, _ := stdecdsa.SignASN1(lcryptotest.NewRand(3), k, hash[:])
	f.Add(hash[:], sig)
	v := new(P256Verifier)
	f.Fuzz(func(t *testing.T, hash, sig []byte) {
		if len(hash) == 0 {
			return // crypto/ecdsa accepts some empty hashes by convention; lcrypto rejects them.
		}
		agree(t, v, &k.PublicKey, pub, hash, sig)
	})
}
