//go:debug cryptocustomrand=1

package ecdsa

import (
	"bytes"
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

type signer interface {
	SetKey(d []byte) error
	PublicKey() ([]byte, error)
	SignASN1(sig, hash []byte, rand io.Reader) (int, error)
	Zeroize()
}

var signers = []struct {
	name    string
	curve   elliptic.Curve
	maxSize int
	new     func() signer
	zero    func(signer) bool
}{
	{"P-256", elliptic.P256(), P256SignatureMaxSize, func() signer { return new(P256Signer) },
		func(s signer) bool { return lcryptotest.IsZero(s.(*P256Signer)) }},
	{"P-384", elliptic.P384(), P384SignatureMaxSize, func() signer { return new(P384Signer) },
		func(s signer) bool { return lcryptotest.IsZero(s.(*P384Signer)) }},
}

func privBytes(k *stdecdsa.PrivateKey) []byte {
	return k.D.FillBytes(make([]byte, (k.Curve.Params().BitSize+7)/8))
}

// TestSignDifferential checks signatures are byte for byte crypto/ecdsa's:
// deterministic ones (RFC 6979) with a nil rand, hedged ones with the same
// entropy, which crypto/ecdsa takes from the caller under cryptocustomrand=1
// after randutil.MaybeReadByte, which discards one byte half of the time.
func TestSignDifferential(t *testing.T) {
	// Under TinyGo, which ignores //go:debug, crypto/ecdsa ignores the Reader.
	probe, _ := newKey(t, elliptic.P256(), 1)
	_, err := stdecdsa.SignASN1(failingReader{}, probe, make([]byte, 32))
	customRand := err != nil
	if !customRand {
		t.Log("crypto/ecdsa ignores custom Readers: hedged signatures not compared")
	}
	for _, c := range signers {
		t.Run(c.name, func(t *testing.T) {
			s := c.new()
			sig := make([]byte, c.maxSize)
			for i := range 10 {
				k, pub := newKey(t, c.curve, byte(40+i))
				if err := s.SetKey(privBytes(k)); err != nil {
					t.Fatal(err)
				}
				gotPub, err := s.PublicKey()
				if err != nil {
					t.Fatal(err)
				}
				lcryptotest.Equal(t, "public key", gotPub, pub)
				for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
					hash := make([]byte, h.Size())
					lcryptotest.NewRand(byte(i)).Read(hash)

					want, err := k.Sign(nil, hash, h)
					if err != nil {
						t.Fatal(err)
					}
					n, err := s.SignASN1(sig, hash, nil)
					if err != nil {
						t.Fatal(err)
					}
					lcryptotest.Equal(t, "deterministic signature", sig[:n], want)

					if !customRand {
						continue
					}
					want, err = stdecdsa.SignASN1(lcryptotest.NewRand(byte(i)), k, hash)
					if err != nil {
						t.Fatal(err)
					}
					n, err = s.SignASN1(sig, hash, lcryptotest.NewRand(byte(i)))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(sig[:n], want) {
						skipped := lcryptotest.NewRand(byte(i))
						skipped.Read(make([]byte, 1))
						n, err = s.SignASN1(sig, hash, skipped)
						if err != nil {
							t.Fatal(err)
						}
						lcryptotest.Equal(t, "hedged signature", sig[:n], want)
					}
					if !stdecdsa.VerifyASN1(&k.PublicKey, hash, sig[:n]) {
						t.Fatal("crypto/ecdsa rejects signature")
					}
				}
			}
		})
	}
}

// TestSignRoundTrip signs with odd hash lengths and verifies with the verifiers.
func TestSignRoundTrip(t *testing.T) {
	for i, c := range signers {
		v := curves[i].new()
		s := c.new()
		k, pub := newKey(t, c.curve, 77)
		if err := s.SetKey(privBytes(k)); err != nil {
			t.Fatal(err)
		}
		rand := lcryptotest.NewRand(5)
		for _, hlen := range []int{1, 20, 31, 47, 49, 64, 100} {
			hash := make([]byte, hlen)
			rand.Read(hash)
			sig := make([]byte, c.maxSize)
			n, err := s.SignASN1(sig, hash, rand)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.VerifyASN1(pub, hash, sig[:n]); err != nil {
				t.Errorf("%s: hash of %d bytes: %v", c.name, hlen, err)
			}
			if !stdecdsa.VerifyASN1(&k.PublicKey, hash, sig[:n]) {
				t.Errorf("%s: hash of %d bytes: crypto/ecdsa rejects", c.name, hlen)
			}
		}
	}
}

func TestSignErrors(t *testing.T) {
	for _, c := range signers {
		t.Run(c.name, func(t *testing.T) {
			n := c.curve.Params().N
			size := (n.BitLen() + 7) / 8
			s := c.new()
			hash := make([]byte, 32)
			sig := make([]byte, c.maxSize)
			if _, err := s.SignASN1(sig, hash, nil); err == nil {
				t.Error("signed without a key")
			}
			for _, tc := range []struct {
				name string
				d    []byte
				ok   bool
			}{
				{"zero", make([]byte, size), false},
				{"n", n.Bytes(), false},
				{"too long", append([]byte{1}, make([]byte, size)...), false},
				{"one", []byte{1}, true},
				{"n-1", new(big.Int).Sub(n, big.NewInt(1)).Bytes(), true},
			} {
				if err := s.SetKey(tc.d); (err == nil) != tc.ok {
					t.Errorf("SetKey %s: %v", tc.name, err)
				}
			}
			k, _ := newKey(t, c.curve, 3)
			if err := s.SetKey(privBytes(k)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SignASN1(sig, nil, nil); err == nil {
				t.Error("signed empty hash")
			}
			if _, err := s.SignASN1(sig, hash[:20], nil); err == nil {
				t.Error("deterministic signature over a 20 byte hash")
			}
			need, err := s.SignASN1(sig[:8], hash, nil)
			if !errors.Is(err, io.ErrShortBuffer) || need < 8 || need > c.maxSize {
				t.Errorf("short buffer: %d %v", need, err)
			}
			if _, err := s.SignASN1(sig, hash, failingReader{}); err == nil {
				t.Error("signed with failing entropy")
			}
			// Deterministic signing is a pure function of key and hash.
			n1, _ := s.SignASN1(sig, hash, nil)
			first := bytes.Clone(sig[:n1])
			n2, _ := s.SignASN1(sig, hash, nil)
			lcryptotest.Equal(t, "repeat", sig[:n2], first)

			if allocs := testing.AllocsPerRun(3, func() {
				if _, err := s.SignASN1(sig, hash, lcryptotest.NewRand(1)); err != nil {
					t.Fatal(err)
				}
			}); allocs > 1 { // NewRand allocates.
				t.Errorf("SignASN1 allocated %v times per run", allocs)
			}
			if allocs := testing.AllocsPerRun(3, func() {
				if _, err := s.SignASN1(sig, hash, nil); err != nil {
					t.Fatal(err)
				}
			}); allocs != 0 {
				t.Errorf("deterministic SignASN1 allocated %v times per run", allocs)
			}
			s.Zeroize()
			if !c.zero(s) {
				t.Error("Zeroize left non-zero bytes")
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }
