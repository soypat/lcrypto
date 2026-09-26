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

type verifier interface {
	VerifyASN1(pub, hash, sig []byte) error
}

// curves are the verifiers under test, each against crypto/ecdsa on its curve.
var curves = []struct {
	name  string
	curve elliptic.Curve
	new   func() verifier
}{
	{"P-256", elliptic.P256(), func() verifier { return new(P256Verifier) }},
	{"P-384", elliptic.P384(), func() verifier { return new(P384Verifier) }},
}

func newKey(t testing.TB, c elliptic.Curve, seed byte) (*stdecdsa.PrivateKey, []byte) {
	k, err := stdecdsa.GenerateKey(c, lcryptotest.NewRand(seed))
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
func agree(t testing.TB, v verifier, std *stdecdsa.PublicKey, pub, hash, sig []byte) bool {
	t.Helper()
	got := v.VerifyASN1(pub, hash, sig) == nil
	want := stdecdsa.VerifyASN1(std, hash, sig)
	if got != want {
		t.Fatalf("lcrypto %v, crypto/ecdsa %v\npub %x\nhash %x\nsig %x", got, want, pub, hash, sig)
	}
	return got
}

func TestDifferential(t *testing.T) {
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			rand := lcryptotest.NewRand(6)
			v := c.new()
			for i := range 30 {
				k, pub := newKey(t, c.curve, byte(i))
				for _, hlen := range []int{1, 20, 32, 47, 48, 49, 64} {
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
		})
	}
}

func TestEdgeCases(t *testing.T) {
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			n := c.curve.Params().N
			k, pub := newKey(t, c.curve, 99)
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
			bits := n.BitLen()
			cases := []struct {
				name string
				sig  []byte
			}{
				{"valid", sig},
				{"high s", der(parsed.R, new(big.Int).Sub(n, parsed.S))},
				{"r zero", der(big.NewInt(0), parsed.S)},
				{"s zero", der(parsed.R, big.NewInt(0))},
				{"r = n", der(n, parsed.S)},
				{"s = n", der(parsed.R, n)},
				{"r + n", der(new(big.Int).Add(parsed.R, n), parsed.S)},
				{"r = n-1", der(new(big.Int).Sub(n, one), parsed.S)},
				{"s = 1", der(parsed.R, one)},
				{"negative r", der(new(big.Int).Neg(parsed.R), parsed.S)},
				{"r 2^bits", der(new(big.Int).Lsh(one, uint(bits)), parsed.S)},
				{"trailing", append(append([]byte{}, sig...), 0)},
				{"empty", nil},
				{"truncated", sig[:len(sig)-1]},
				{"sequence only", []byte{0x30, 0x00}},
				{"one integer", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
				{"indefinite len", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00}},
			}
			v := c.new()
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) { agree(t, v, &k.PublicKey, pub, hash[:], tc.sig) })
			}
			if v.VerifyASN1(pub, nil, sig) == nil {
				t.Error("accepted empty hash")
			}
			bad := append([]byte{}, pub...)
			bad[len(bad)/2] ^= 1
			if v.VerifyASN1(bad, hash[:], sig) == nil {
				t.Error("accepted public key off the curve")
			}
			if v.VerifyASN1(pub[:len(pub)-1], hash[:], sig) == nil {
				t.Error("accepted truncated public key")
			}
		})
	}
}

func TestAllocs(t *testing.T) {
	for _, c := range curves {
		k, pub := newKey(t, c.curve, 7)
		hash := sha256.Sum256([]byte("allocs"))
		sig, _ := stdecdsa.SignASN1(lcryptotest.NewRand(2), k, hash[:])
		v := c.new()
		if allocs := testing.AllocsPerRun(5, func() {
			if err := v.VerifyASN1(pub, hash[:], sig); err != nil {
				t.Fatal(err)
			}
		}); allocs != 0 {
			t.Errorf("%s: VerifyASN1 allocated %v times per run", c.name, allocs)
		}
	}
}

func FuzzDifferential(f *testing.F) {
	type key struct {
		std *stdecdsa.PublicKey
		pub []byte
		v   verifier
	}
	var keys []key
	for _, c := range curves {
		k, pub := newKey(f, c.curve, 8)
		hash := sha256.Sum256([]byte("fuzz"))
		sig, _ := stdecdsa.SignASN1(lcryptotest.NewRand(3), k, hash[:])
		f.Add(uint8(len(keys)), hash[:], sig)
		keys = append(keys, key{&k.PublicKey, pub, c.new()})
	}
	f.Fuzz(func(t *testing.T, curve uint8, hash, sig []byte) {
		if len(hash) == 0 {
			return // crypto/ecdsa accepts some empty hashes by convention; lcrypto rejects them.
		}
		k := keys[int(curve)%len(keys)]
		agree(t, k.v, k.std, k.pub, hash, sig)
	})
}
