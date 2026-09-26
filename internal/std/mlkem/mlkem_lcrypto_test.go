package mlkem

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"math/rand/v2"
	"testing"
)

// TestDifferential compares key generation, encapsulation and decapsulation,
// implicit rejection included, against the standard library.
func TestDifferential(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{1, 2})
	var dk DecapsulationKey768
	var ek EncapsulationKey768
	var ct [CiphertextSize768]byte
	for range 20 {
		var seed [SeedSize]byte
		var m [32]byte
		rng.Read(seed[:])
		rng.Read(m[:])
		want, err := stdmlkem.NewDecapsulationKey768(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := InitDecapsulationKey768(&dk, seed[:]); err != nil {
			t.Fatal(err)
		}
		ekBytes := dk.AppendEncapsulationKey(nil)
		if !bytes.Equal(ekBytes, want.EncapsulationKey().Bytes()) {
			t.Fatal("encapsulation key mismatch")
		}
		if err := ParseEncapsulationKey768(&ek, ekBytes); err != nil {
			t.Fatal(err)
		}
		K := ek.EncapsulateTo(&ct, &m)
		wantK, wantCT, err := mlkemtest.Encapsulate768(want.EncapsulationKey(), m[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(K, wantK) || !bytes.Equal(ct[:], wantCT) {
			t.Fatal("encapsulation mismatch")
		}
		got, err := dk.Decapsulate(ct[:])
		if err != nil || !bytes.Equal(got, wantK) {
			t.Fatal("decapsulation mismatch", err)
		}
		ct[rng.Uint64()%uint64(len(ct))] ^= 1 << (rng.Uint64() % 8) // Implicit rejection path.
		got, err = dk.Decapsulate(ct[:])
		wantRej, err2 := want.Decapsulate(ct[:])
		if err != nil || err2 != nil || !bytes.Equal(got, wantRej) {
			t.Fatal("implicit rejection mismatch", err, err2)
		}
	}
}
