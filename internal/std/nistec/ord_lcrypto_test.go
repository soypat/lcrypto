package nistec

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

// TestOrdModulus checks ordModulus against math/big modulo the NIST curve orders.
func TestOrdModulus(t *testing.T) {
	rand := lcryptotest.NewRand(9)
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		n := c.Params().N
		size := (n.BitLen() + 7) / 8
		var m ordModulus
		m.init(n.FillBytes(make([]byte, size)))
		elem := func(x *big.Int) *ordElem {
			var e ordElem
			if !m.setCanonical(&e, x.Bytes()) {
				t.Fatalf("%s: setCanonical(%x) failed", c.Params().Name, x)
			}
			return &e
		}
		toBig := func(e *ordElem) *big.Int {
			b := make([]byte, size)
			m.putBytes(b, e)
			return new(big.Int).SetBytes(b)
		}
		nm1 := new(big.Int).Sub(n, big.NewInt(1))
		values := []*big.Int{big.NewInt(1), big.NewInt(2), nm1, new(big.Int).Rsh(n, 1)}
		for range 20 {
			b := make([]byte, size)
			rand.Read(b)
			v := new(big.Int).Mod(new(big.Int).SetBytes(b), n)
			if v.Sign() != 0 {
				values = append(values, v)
			}
		}
		for _, x := range values {
			var inv ordElem
			m.inverse(&inv, elem(x))
			if want := new(big.Int).ModInverse(x, n); toBig(&inv).Cmp(want) != 0 {
				t.Fatalf("%s: inverse(%x)", c.Params().Name, x)
			}
			for _, y := range values[:6] {
				var z ordElem
				m.mul(&z, elem(x), elem(y))
				if want := new(big.Int).Mod(new(big.Int).Mul(x, y), n); toBig(&z).Cmp(want) != 0 {
					t.Fatalf("%s: mul(%x, %x)", c.Params().Name, x, y)
				}
			}
		}
		for _, tc := range []struct {
			name string
			b    []byte
			ok   bool
		}{
			{"zero", []byte{0}, false},
			{"n", n.Bytes(), false},
			{"n-1", nm1.Bytes(), true},
			{"too long", append([]byte{0}, nm1.Bytes()...), false},
		} {
			var e ordElem
			if m.setCanonical(&e, tc.b) != tc.ok {
				t.Errorf("%s: setCanonical %s: want %v", c.Params().Name, tc.name, tc.ok)
			}
		}
		// hashToScalar is crypto/ecdsa's hashToNat: leftmost bitLen bits, reduced.
		for _, hlen := range []int{1, 20, 32, 48, 64, 66, 80} {
			hash := make([]byte, hlen)
			rand.Read(hash)
			var buf [ordLimbs * 8]byte
			var e ordElem
			m.hashToScalar(&e, hash, &buf)
			want := new(big.Int).SetBytes(hash)
			if excess := hlen*8 - n.BitLen(); excess > 0 {
				want.Rsh(want, uint(excess))
			}
			want.Mod(want, n)
			if toBig(&e).Cmp(want) != 0 {
				t.Errorf("%s: hashToScalar of %d bytes: got %x, want %x", c.Params().Name, hlen, toBig(&e), want)
			}
		}
	}
}
