package ed25519

import (
	"bufio"
	"compress/gzip"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestRFC8032 checks the RFC 8032 section 7.1 test vectors.
func TestRFC8032(t *testing.T) {
	for _, tc := range []struct{ name, seed, pub, msg, sig string }{
		{"test 1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"test 2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
			"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
		{"test 3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
			"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	} {
		t.Run(tc.name, func(t *testing.T) { checkVector(t, unhex(tc.seed), unhex(tc.pub), unhex(tc.msg), unhex(tc.sig)) })
	}
}

func checkVector(t *testing.T, seed, pub, msg, sig []byte) {
	t.Helper()
	var s Signer
	if err := s.SetSeed(seed); err != nil {
		t.Fatal(err)
	}
	gotPub, _ := s.PublicKey()
	lcryptotest.Equal(t, "public key", gotPub, pub)
	var got [SignatureSize]byte
	if err := s.Sign(got[:], msg); err != nil {
		t.Fatal(err)
	}
	lcryptotest.Equal(t, "signature", got[:], sig)
	var v Verifier
	if err := v.Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
}

// TestSignInput runs crypto/ed25519's sign.input.gz, from the fetched Go tree.
func TestSignInput(t *testing.T) {
	f, err := os.Open("../local/_go/crypto/ed25519/testdata/sign.input.gz")
	if err != nil {
		t.Skip("Go testdata missing; run `go run ./internal/cmd/lcryptogen fetch`")
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(z)
	n := 0
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		priv, msg, sig := unhex(parts[0]), unhex(parts[2]), unhex(parts[3])
		checkVector(t, priv[:SeedSize], unhex(parts[1]), msg, sig[:SignatureSize])
		n++
	}
	if n < 100 {
		t.Fatalf("only %d vectors", n)
	}
}

// TestDifferential checks signatures and verdicts against crypto/ed25519,
// including altered messages, signatures and keys.
func TestDifferential(t *testing.T) {
	rand := lcryptotest.NewRand(3)
	var s Signer
	var v Verifier
	for i := range 50 {
		seed := make([]byte, SeedSize)
		rand.Read(seed)
		priv := stded25519.NewKeyFromSeed(seed)
		pub := priv.Public().(stded25519.PublicKey)
		msg := make([]byte, i*7)
		rand.Read(msg)
		if err := s.SetSeed(seed); err != nil {
			t.Fatal(err)
		}
		var sig [SignatureSize]byte
		if err := s.Sign(sig[:], msg); err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "signature", sig[:], stded25519.Sign(priv, msg))
		for _, edit := range []struct {
			name string
			pub  []byte
			msg  []byte
			sig  []byte
		}{
			{"valid", pub, msg, sig[:]},
			{"msg", pub, flip(append(msg, 0), i), sig[:]},
			{"R", pub, msg, flip(sig[:], i%32)},
			{"S", pub, msg, flip(sig[:], 32+i%32)},
			{"S high bits", pub, msg, flip(sig[:], 63+(i%3)*0)},
			{"pub", flip(pub, i%32), msg, sig[:]},
			{"short sig", pub, msg, sig[:63]},
			{"short pub", pub[:31], msg, sig[:]},
		} {
			got := v.Verify(edit.pub, edit.msg, edit.sig) == nil
			want := len(edit.pub) == 32 && stded25519.Verify(edit.pub, edit.msg, edit.sig)
			if got != want {
				t.Fatalf("%d %s: got %v, crypto/ed25519 %v", i, edit.name, got, want)
			}
		}
	}
}

func flip(b []byte, i int) []byte {
	b = append([]byte(nil), b...)
	b[i%len(b)] ^= 1 << (i % 8)
	return b
}

func TestAllocsZeroize(t *testing.T) {
	var s Signer
	var v Verifier
	seed := make([]byte, SeedSize)
	var sig [SignatureSize]byte
	msg := []byte("allocs")
	if allocs := testing.AllocsPerRun(5, func() {
		if err := s.SetSeed(seed); err != nil {
			t.Fatal(err)
		}
		if err := s.Sign(sig[:], msg); err != nil {
			t.Fatal(err)
		}
		pub, _ := s.PublicKey()
		if err := v.Verify(pub, msg, sig[:]); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("allocated %v times per run", allocs)
	}
	if s.Sign(sig[:10], msg) == nil {
		t.Error("signed into a short buffer")
	}
	if s.SetSeed(seed[:31]) == nil {
		t.Error("accepted short seed")
	}
	s.SetSeed(seed)
	s.Zeroize()
	if !lcryptotest.IsZero(&s) {
		t.Error("Zeroize left non-zero bytes")
	}
	if s.Sign(sig[:], msg) == nil {
		t.Error("signed after Zeroize")
	}
}

func FuzzVerify(f *testing.F) {
	priv := stded25519.NewKeyFromSeed(make([]byte, SeedSize))
	msg := []byte("fuzz")
	f.Add([]byte(priv.Public().(stded25519.PublicKey)), msg, stded25519.Sign(priv, msg))
	var v Verifier
	f.Fuzz(func(t *testing.T, pub, msg, sig []byte) {
		got := v.Verify(pub, msg, sig) == nil
		want := len(pub) == PublicKeySize && stded25519.Verify(pub, msg, sig)
		if got != want {
			t.Fatalf("got %v, crypto/ed25519 %v", got, want)
		}
	})
}
