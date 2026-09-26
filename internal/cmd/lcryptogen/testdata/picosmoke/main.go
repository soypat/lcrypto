// Command picosmoke exercises every lcrypto primitive so that TinyGo's
// -print-allocs reports each heap allocation site reachable from them.
package main

import (
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/aesgcm"
	"github.com/soypat/lcrypto/chacha20poly1305"
	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/p256"
	"github.com/soypat/lcrypto/rsa"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/sha512"
	"github.com/soypat/lcrypto/x25519"
	"github.com/soypat/lcrypto/x509"
)

var (
	a  aesgcm.Cipher
	c  chacha20poly1305.Cipher
	h  sha256.Digest
	h5 sha512.Digest

	xClient, xServer x25519.Exchanger
	pClient, pServer p256.Exchanger
	verifier         ecdsa.P256Verifier
	rsaVerifier      rsa.Verifier
	modulus          [256]byte
	certVerifier     x509.Verifier
	certs            x509.Chain

	cs     [p256.ShareSize]byte
	ss     [p256.ShareSize]byte
	shared [2][p256.SharedSize]byte
)

// counter is a deterministic entropy source; real firmware reads a TRNG.
type counter struct{ n byte }

func (r *counter) Read(b []byte) (int, error) {
	for i := range b {
		r.n++
		b[i] = r.n
	}
	return len(b), nil
}

var rand counter

func main() {
	var key [32]byte
	var nonce [12]byte
	var buf [64 + 16]byte
	a.Rekey(key[:])
	c.Rekey(key[:])
	out := a.Seal(buf[:0], nonce[:], buf[:64], nil)
	a.Open(buf[:0], nonce[:], out, nil)
	out = c.Seal(buf[:0], nonce[:], out[:64], nil)
	c.Open(buf[:0], nonce[:], out, nil)
	h.Init()
	h.Write(out)
	h5.Init384()
	h5.Write(h.Sum(buf[:0]))
	h5.Sum(buf[:0])
	h5.Zeroize()
	h.Zeroize()
	a.Zeroize()
	c.Zeroize()

	println(exchange(&xClient, &xServer), exchange(&pClient, &pServer))
	// Public key share doubles as a P-256 public key; the signature is garbage.
	println(verifier.VerifyASN1(cs[:], shared[0][:], ss[:]) == nil)
	// Odd 2048 bit modulus; the signature is garbage but runs the public key operation.
	for i := range modulus {
		modulus[i] = byte(i) | 0x81
	}
	println(rsaVerifier.VerifyPKCS1v15(modulus[:], 65537, rsa.SHA256, shared[0][:], modulus[:]) == nil,
		rsaVerifier.VerifyPSS(modulus[:], 65537, rsa.SHA256, shared[0][:], modulus[:]) == nil)
	// Garbage certificates: the chain is parsed and rejected.
	certs = x509.Chain{modulus[:], modulus[:]}
	certVerifier.Roots = &certs // A pointer: boxing the slice would allocate.
	println(certVerifier.VerifyPeer(&certs, x509.SchemeECDSAP256SHA256, true, modulus[:8], modulus[:], modulus[:]) == nil)
}

func exchange(client, server lcrypto.Exchanger) bool {
	n, err := client.ClientGenerateRekey(cs[:], &rand)
	if err != nil {
		return false
	}
	nss, nShared, err := server.ServerSharedRekey(ss[:], shared[0][:], cs[:n], &rand)
	if err != nil {
		return false
	}
	if _, err = client.ClientShared(shared[1][:], ss[:nss]); err != nil {
		return false
	}
	client.Zeroize()
	server.Zeroize()
	return string(shared[0][:nShared]) == string(shared[1][:nShared])
}
