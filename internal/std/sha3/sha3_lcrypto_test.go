package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"math/rand/v2"
	"testing"
)

func TestDifferential(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{1, 2})
	msg := make([]byte, 700)
	rng.Read(msg)
	var d256, d512 Digest
	var s128, s256 SHAKE
	for n := 0; n <= len(msg); n += 13 {
		d256.Init256()
		d512.Init512()
		s128.InitShake128()
		s256.InitShake256()
		for p := msg[:n]; len(p) > 0; {
			k := min(len(p), 1+int(rng.Uint64()%uint64(200)))
			d256.Write(p[:k])
			d512.Write(p[:k])
			s128.Write(p[:k])
			s256.Write(p[:k])
			p = p[k:]
		}
		w256, w512 := stdsha3.Sum256(msg[:n]), stdsha3.Sum512(msg[:n])
		if !bytes.Equal(d256.Sum(nil), w256[:]) || !bytes.Equal(d512.Sum(nil), w512[:]) {
			t.Fatal("SHA3 mismatch at", n)
		}
		got, want := make([]byte, 300), make([]byte, 300)
		s128.Read(got)
		want = stdsha3.SumSHAKE128(msg[:n], len(want))
		if !bytes.Equal(got, want) {
			t.Fatal("SHAKE128 mismatch at", n)
		}
		s256.Read(got)
		want = stdsha3.SumSHAKE256(msg[:n], len(want))
		if !bytes.Equal(got, want) {
			t.Fatal("SHAKE256 mismatch at", n)
		}
	}
}
