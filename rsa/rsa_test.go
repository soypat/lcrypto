package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

var keys = map[int]*stdrsa.PrivateKey{}

func key(t testing.TB, bits int) *stdrsa.PrivateKey {
	if k, ok := keys[bits]; ok {
		return k
	}
	k, err := stdrsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys[bits] = k
	return k
}

type hashCase struct {
	h   Hash
	std crypto.Hash
	sum func([]byte) []byte
}

var hashes = []hashCase{
	{SHA256, crypto.SHA256, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
	{SHA384, crypto.SHA384, func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }},
	{SHA512, crypto.SHA512, func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }},
}

// TestDifferential signs with crypto/rsa and requires lcrypto to agree with
// crypto/rsa's verdict on the signature and on single bit mutations of it.
func TestDifferential(t *testing.T) {
	rng := lcryptotest.NewRand(9)
	v := new(Verifier)
	pss := &stdrsa.PSSOptions{SaltLength: stdrsa.PSSSaltLengthEqualsHash}
	for _, bits := range []int{1024, 1536, 2048, 2049, 3072, 4096} {
		k := key(t, bits)
		n, e := k.N.Bytes(), k.E
		for _, hc := range hashes {
			msg := make([]byte, 50)
			rng.Read(msg)
			hashed := hc.sum(msg)
			sig1, err := stdrsa.SignPKCS1v15(rand.Reader, k, hc.std, hashed)
			if err != nil {
				t.Fatal(err)
			}
			sig2, err := stdrsa.SignPSS(rand.Reader, k, hc.std, hashed, pss)
			if err == stdrsa.ErrMessageTooLong {
				sig2 = make([]byte, len(sig1)) // Key too small for this digest and salt: must not verify.
			} else if err != nil {
				t.Fatal(err)
			}
			for i := range 4 {
				if i > 0 { // Mutate signature, digest or modulus.
					for _, b := range [][]byte{sig1, sig2, hashed} {
						b[rng.Uint64()%uint64(len(b))] ^= 1 << (rng.Uint64() % 8)
					}
				}
				got := v.VerifyPKCS1v15(n, e, hc.h, hashed, sig1) == nil
				want := stdrsa.VerifyPKCS1v15(&k.PublicKey, hc.std, hashed, sig1) == nil
				if got != want || (i == 0 && !got) {
					t.Fatalf("%d bits %v PKCS1v15 #%d: lcrypto %v crypto/rsa %v", bits, hc.std, i, got, want)
				}
				got = v.VerifyPSS(n, e, hc.h, hashed, sig2) == nil
				want = stdrsa.VerifyPSS(&k.PublicKey, hc.std, hashed, sig2, pss) == nil
				if got != want || (i == 0 && !got && err == nil) {
					t.Fatalf("%d bits %v PSS #%d: lcrypto %v crypto/rsa %v", bits, hc.std, i, got, want)
				}
			}
		}
	}
}

func TestRejects(t *testing.T) {
	k := key(t, 2048)
	hashed := make([]byte, 32)
	sig, _ := stdrsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hashed)
	n := k.N.Bytes()
	v := new(Verifier)
	cases := map[string]error{
		"short sig":   v.VerifyPKCS1v15(n, k.E, SHA256, hashed, sig[1:]),
		"even e":      v.VerifyPKCS1v15(n, 4, SHA256, hashed, sig),
		"e 1":         v.VerifyPKCS1v15(n, 1, SHA256, hashed, sig),
		"sig >= n":    v.VerifyPKCS1v15(n, k.E, SHA256, hashed, n),
		"wrong hash":  v.VerifyPKCS1v15(n, k.E, SHA384, hashed, sig),
		"no hash":     v.VerifyPKCS1v15(n, k.E, 0, hashed, sig),
		"8192 bits":   v.VerifyPKCS1v15(make([]byte, 1024), k.E, SHA256, hashed, sig),
		"512 bits":    v.VerifyPKCS1v15(bytes.Repeat([]byte{0xff}, 64), 65537, SHA256, hashed, sig[:64]),
		"even n":      v.VerifyPKCS1v15(append(n[:len(n)-1:len(n)-1], 2), k.E, SHA256, hashed, sig),
		"pss as v1.5": v.VerifyPSS(n, k.E, SHA256, hashed, sig),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Leading zeros on the modulus, as in ASN.1 INTEGER encodings, are accepted.
	if err := v.VerifyPKCS1v15(append([]byte{0}, n...), k.E, SHA256, hashed, sig); err != nil {
		t.Error("leading zero modulus:", err)
	}
}

func TestAllocs(t *testing.T) {
	k := key(t, 4096)
	hashed := make([]byte, 32)
	sig1, _ := stdrsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hashed)
	sig2, _ := stdrsa.SignPSS(rand.Reader, k, crypto.SHA256, hashed, &stdrsa.PSSOptions{SaltLength: stdrsa.PSSSaltLengthEqualsHash})
	n := k.N.Bytes()
	v := new(Verifier)
	allocs := testing.AllocsPerRun(3, func() {
		if v.VerifyPKCS1v15(n, k.E, SHA256, hashed, sig1) != nil || v.VerifyPSS(n, k.E, SHA256, hashed, sig2) != nil {
			t.Fatal("verification failed")
		}
	})
	if allocs != 0 {
		t.Errorf("verification allocated %v times per run", allocs)
	}
}
