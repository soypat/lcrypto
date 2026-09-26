package lcryptotest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lcrypto"
)

// Chain is an in-memory lcrypto.CertChain of DER certificates, leaf first.
type Chain [][]byte

func (c Chain) NumCerts() int { return len(c) }

func (c Chain) Cert(dst []byte, i int) (int, error) {
	if len(dst) < len(c[i]) {
		return len(c[i]), io.ErrShortBuffer
	}
	return copy(dst, c[i]), nil
}

func (c Chain) CertView(i int) ([]byte, error) { return c[i], nil }

// Cert is a test certificate and its private key.
type Cert struct {
	DER  []byte
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Epoch is the reference time of certificates made with [Template].
var Epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var serial int64

// Template returns a certificate template named cn, valid for a year around
// [Epoch]. CAs get basic constraints and the certificate signing key usage.
func Template(cn string, isCA bool) *x509.Certificate {
	serial++
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             Epoch.Add(-180 * 24 * time.Hour),
		NotAfter:              Epoch.Add(180 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		t.KeyUsage |= x509.KeyUsageCertSign
	}
	return t
}

// NewCert issues template for key, signed by parent or self-signed if parent is nil.
func NewCert(t testing.TB, template *x509.Certificate, key crypto.Signer, parent *Cert) *Cert {
	t.Helper()
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{DER: der, Cert: cert, Key: key}
}

var (
	keyMu   sync.Mutex
	rsaKeys = map[int][]*rsa.PrivateKey{}
)

// RSAKey returns the i'th RSA test key of the given size, generated once per
// process: key generation is slow.
func RSAKey(t testing.TB, bits, i int) *rsa.PrivateKey {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	for len(rsaKeys[bits]) <= i {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		rsaKeys[bits] = append(rsaKeys[bits], k)
	}
	return rsaKeys[bits][i]
}

// ECKey returns a new ECDSA key on curve.
func ECKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// CertificateVerifyMsg returns the RFC 8446 4.4.3 content signed in CertificateVerify.
func CertificateVerifyMsg(server bool, transcriptHash []byte) []byte {
	msg := make([]byte, 64, 64+34+len(transcriptHash))
	for i := range msg {
		msg[i] = 0x20
	}
	if server {
		msg = append(msg, "TLS 1.3, server CertificateVerify"...)
	} else {
		msg = append(msg, "TLS 1.3, client CertificateVerify"...)
	}
	msg = append(msg, 0)
	return append(msg, transcriptHash...)
}

// SignCertificateVerify signs msg with key under the TLS signature scheme as
// crypto/tls does. PKCS #1 v1.5 schemes, not allowed in TLS 1.3, are supported
// to test their rejection.
func SignCertificateVerify(t testing.TB, key crypto.Signer, scheme uint16, msg []byte) []byte {
	t.Helper()
	var h crypto.Hash
	switch scheme {
	case 0x0403, 0x0804, 0x0401:
		h = crypto.SHA256
	case 0x0503, 0x0805, 0x0501:
		h = crypto.SHA384
	case 0x0603, 0x0806, 0x0601:
		h = crypto.SHA512
	default:
		t.Fatalf("scheme %#04x", scheme)
	}
	var digest []byte
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		digest = d[:]
	default:
		d := sha512.Sum512(msg)
		digest = d[:]
	}
	var opts crypto.SignerOpts = h
	if scheme>>8 == 8 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// VerifierCase is a peer authentication a Verifier must accept.
type VerifierCase struct {
	Chain        Chain
	Scheme       uint16
	PeerIsServer bool
	Name         []byte
	Msg, Sig     []byte
}

// Verifier checks the lcrypto.Verifier contract: v accepts c, and rejects it
// with any of the signature, message, scheme or name altered, and with no
// chain or a damaged leaf. Verification does not
// allocate and gives the same results under concurrent use.
func Verifier(t *testing.T, v lcrypto.Verifier, c VerifierCase) {
	t.Helper()
	verify := func(c VerifierCase) error {
		return v.VerifyPeer(c.Chain, c.Scheme, c.PeerIsServer, c.Name, c.Msg, c.Sig)
	}
	if err := verify(c); err != nil {
		t.Fatal("valid case rejected:", err)
	}
	flip := func(b []byte, i int) []byte {
		b = append([]byte(nil), b...)
		b[i%len(b)] ^= 1
		return b
	}
	type edit struct {
		name string
		edit func(*VerifierCase)
	}
	bad := []edit{
		{"sig first byte", func(c *VerifierCase) { c.Sig = flip(c.Sig, 0) }},
		{"sig last byte", func(c *VerifierCase) { c.Sig = flip(c.Sig, len(c.Sig)-1) }},
		{"sig truncated", func(c *VerifierCase) { c.Sig = c.Sig[:len(c.Sig)-1] }},
		{"sig empty", func(c *VerifierCase) { c.Sig = nil }},
		{"msg", func(c *VerifierCase) { c.Msg = flip(c.Msg, len(c.Msg)-1) }},
		{"msg context", func(c *VerifierCase) { c.Msg = flip(c.Msg, 70) }},
		{"scheme", func(c *VerifierCase) { c.Scheme ^= 0x0100 }},
		{"scheme unknown", func(c *VerifierCase) { c.Scheme = 0xfefe }},
		{"no certs", func(c *VerifierCase) { c.Chain = nil }},
		{"leaf truncated", func(c *VerifierCase) {
			c.Chain = append(Chain{c.Chain[0][:len(c.Chain[0])-1]}, c.Chain[1:]...)
		}},
		{"leaf signature", func(c *VerifierCase) {
			c.Chain = append(Chain{flip(c.Chain[0], len(c.Chain[0])-1)}, c.Chain[1:]...)
		}},
		{"leaf tbs", func(c *VerifierCase) {
			c.Chain = append(Chain{flip(c.Chain[0], len(c.Chain[0])/2)}, c.Chain[1:]...)
		}},
	}
	if c.PeerIsServer {
		bad = append(bad,
			edit{"name", func(c *VerifierCase) { c.Name = append([]byte("x"), c.Name...) }},
			edit{"no name", func(c *VerifierCase) { c.Name = nil }},
		)
	}
	for _, b := range bad {
		bc := c
		b.edit(&bc)
		if err := verify(bc); err == nil {
			t.Errorf("%s: accepted", b.name)
		}
	}
	var chain lcrypto.CertChain = c.Chain // Box once: conversion allocates.
	if allocs := testing.AllocsPerRun(5, func() {
		if err := v.VerifyPeer(chain, c.Scheme, c.PeerIsServer, c.Name, c.Msg, c.Sig); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("VerifyPeer allocated %v times per run", allocs)
	}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				bc := c
				if (g+i)%2 == 1 {
					bc.Sig = flip(bc.Sig, i)
				}
				if err := verify(bc); (err == nil) != (bc.Sig[i%len(bc.Sig)] == c.Sig[i%len(c.Sig)]) {
					t.Errorf("concurrent verification: got %v", err)
				}
			}
		}()
	}
	wg.Wait()
}
