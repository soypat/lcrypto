package x509_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"
	"time"

	"github.com/soypat/lcrypto"
	lecdsa "github.com/soypat/lcrypto/ecdsa"
	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

func TestCredential(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("rsa", "root", true, nil, nil)
	inter := p.issue("p384", "inter", true, root, nil)
	verifier := &lx509.Verifier{Roots: lt.Chain{root.DER}, Time: func() time.Time { return lt.Epoch }}
	for _, c := range []struct {
		kind   string
		scheme uint16
		hash   crypto.Hash
	}{
		{"ec", lx509.SchemeECDSAP256SHA256, crypto.SHA256},
		{"p384", lx509.SchemeECDSAP384SHA384, crypto.SHA384},
		{"ed25519", lx509.SchemeEd25519, 0},
	} {
		leaf := p.issue(c.kind, "leaf "+c.kind, false, inter, nil)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
		if err != nil {
			t.Fatal(err)
		}
		formats := []struct {
			name string
			der  []byte
		}{{"PKCS8", pkcs8}}
		if key, ok := leaf.Key.(*ecdsa.PrivateKey); ok {
			sec1, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			formats = append(formats, struct {
				name string
				der  []byte
			}{"SEC1", sec1})
		}
		chain := lt.Chain{leaf.DER, inter.DER}
		for _, format := range formats {
			for _, deterministic := range []bool{true, false} {
				name := c.kind + "/" + format.name
				if !deterministic {
					name += "/hedged"
				}
				t.Run(name, func(t *testing.T) {
					cred := &lx509.Credential{}
					if !deterministic {
						cred.Rand = lt.NewRand(7)
					}
					if err := cred.SetKey(chain, format.der); err != nil {
						t.Fatal(err)
					}
					lt.Credential(t, cred, verifier, c.scheme, lecdsa.P384SignatureMaxSize)
					if deterministic { // Byte for byte crypto/ecdsa's RFC 6979 signature.
						msg := lt.CertificateVerifyMsg(false, []byte("transcript"))
						sig := make([]byte, lecdsa.P384SignatureMaxSize)
						n, err := cred.Sign(sig, msg, c.scheme)
						if err != nil {
							t.Fatal(err)
						}
						signed := msg
						if c.hash != 0 {
							signed = digest(c.hash, msg)
						}
						want, err := leaf.Key.Sign(nil, signed, c.hash)
						if err != nil {
							t.Fatal(err)
						}
						lt.Equal(t, "signature", sig[:n], want)
					}
					cred.Zeroize()
					if _, err := cred.Sign(make([]byte, 128), []byte("m"), c.scheme); err == nil {
						t.Error("signed after Zeroize")
					}
					if cred.Scheme([]uint16{c.scheme}) != 0 || cred.NumCerts() != 0 {
						t.Error("Zeroize left the credential usable")
					}
					if deterministic && !lt.IsZero(cred) {
						t.Error("Zeroize left non-zero bytes")
					}
				})
			}
		}
	}
}

func digest(h crypto.Hash, msg []byte) []byte {
	if h == crypto.SHA256 {
		d := sha256.Sum256(msg)
		return d[:]
	}
	d := sha512.Sum384(msg)
	return d[:]
}

func TestCredentialSetKeyErrors(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	leaf := p.issue("ec", "leaf", false, root, nil)
	other := p.issue("ec", "other", false, root, nil)
	leaf384 := p.issue("p384", "leaf 384", false, root, nil)
	leafRSA := p.issue("rsa", "leaf RSA", false, root, nil)
	leafEd := p.issue("ed25519", "leaf Ed25519", false, root, nil)
	marshal := func(c *lt.Cert) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(c.Key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sec1 := func(c *lt.Cert) []byte {
		b, err := x509.MarshalECPrivateKey(c.Key.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := marshal(leaf)
	for _, tc := range []struct {
		name  string
		chain lcrypto.CertChain
		key   []byte
	}{
		{"other key", lt.Chain{leaf.DER}, marshal(other)},
		{"P-384 key for P-256 leaf", lt.Chain{leaf.DER}, marshal(leaf384)},
		{"P-256 key for P-384 leaf", lt.Chain{leaf384.DER}, sec1(leaf)},
		{"RSA leaf", lt.Chain{leafRSA.DER}, marshal(leafRSA)},
		{"RSA key", lt.Chain{leaf.DER}, marshal(leafRSA)},
		{"Ed25519 key for P-256 leaf", lt.Chain{leaf.DER}, marshal(leafEd)},
		{"P-256 key for Ed25519 leaf", lt.Chain{leafEd.DER}, marshal(leaf)},
		{"other Ed25519 key", lt.Chain{leafEd.DER}, marshal(p.issue("ed25519", "other Ed25519", false, root, nil))},
		{"no chain", lt.Chain{}, good},
		{"nil chain", nil, good},
		{"garbage leaf", lt.Chain{good}, good},
		{"trailing data", lt.Chain{leaf.DER}, append(append([]byte{}, good...), 0)},
		{"truncated", lt.Chain{leaf.DER}, good[:len(good)-1]},
		{"empty", lt.Chain{leaf.DER}, nil},
	} {
		var cred lx509.Credential
		if err := cred.SetKey(tc.chain, tc.key); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if cred.Scheme([]uint16{lx509.SchemeECDSAP256SHA256, lx509.SchemeECDSAP384SHA384}) != 0 {
			t.Errorf("%s: failed SetKey left a scheme", tc.name)
		}
	}
	var cred lx509.Credential
	if err := cred.SetKey(lt.Chain{leaf.DER}, good); err != nil {
		t.Fatal(err)
	}
	if err := cred.SetKey(lt.Chain{leaf.DER}, marshal(other)); err == nil || cred.NumCerts() != 0 {
		t.Error("failed SetKey kept the previous key")
	}
}
