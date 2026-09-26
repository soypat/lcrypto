package sha256

import (
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

func TestDifferential(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var d, d224 Digest
	d.Init()
	d224.Init224()
	msg := make([]byte, 1000)
	for i := range msg {
		msg[i] = byte(rng.Uint32())
	}
	for n := 0; n <= len(msg); n += 7 {
		d.Reset()
		d224.Reset()
		// Chunked writes exercise the partial block buffer.
		for p := msg[:n]; len(p) > 0; {
			k := min(len(p), 1+rng.IntN(100))
			d.Write(p[:k])
			d224.Write(p[:k])
			p = p[k:]
		}
		want := sha256.Sum256(msg[:n])
		lcryptotest.Equal(t, "SHA-256", d.Sum(nil), want[:])
		want224 := sha256.Sum224(msg[:n])
		lcryptotest.Equal(t, "SHA-224", d224.Sum(nil), want224[:])
	}
}

func TestZeroizeAllocs(t *testing.T) {
	var fresh, d Digest
	fresh.Init()
	d.Init()
	var sum [Size]byte
	msg := []byte("some secret transcript that does not fill a whole block")
	allocs := testing.AllocsPerRun(50, func() {
		d.Write(msg)
		d.Sum(sum[:0])
		d.Zeroize()
	})
	if allocs != 0 {
		t.Errorf("Write/Sum/Zeroize allocated %v times per run", allocs)
	}
	d.Write(msg)
	d.Zeroize()
	if !bytes.Equal(lcryptotest.Bytes(&d), lcryptotest.Bytes(&fresh)) {
		t.Error("Zeroize left buffered input behind")
	}
}
