package x509

import (
	"io"

	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/ed25519"
	"github.com/soypat/lcrypto/rsa"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/sha512"
)

// SignatureVerifier verifies signatures by one kind of public key for a
// [Verifier]. Verifier calls it under its lock after checking alg suits the key
// and the key's size policy, so it needs no lock of its own. It must not be
// shared between Verifiers.
//
// Only the implementations a program names are linked: list in
// [VerifierConfig.Algorithms] just what peers need.
type SignatureVerifier interface {
	// PublicKeyAlgorithm is the key kind verified. It must not change.
	PublicKeyAlgorithm() PublicKeyAlgorithm
	// VerifySignature returns nil if sig is key's signature of msg under alg.
	// msg is unhashed. Do not retain or modify key, msg or sig.
	VerifySignature(key *Certificate, alg SignatureAlgorithm, msg, sig []byte) error
}

// KeySigner signs with one kind of private key for a [Credential]. Credential
// calls it under its lock. It must not be shared between Credentials.
type KeySigner interface {
	// PublicKeyAlgorithm is the key kind signed with. It must not change.
	PublicKeyAlgorithm() PublicKeyAlgorithm
	// SetKey installs private key d, already fitted to size, and returns the
	// public key as Certificate.PublicKey holds it. d is not retained.
	SetKey(d []byte) (pub []byte, err error)
	// Sign writes the signature of unhashed msg into sig, hedged with rand if
	// not nil. If sig is short it writes nothing and returns the needed length
	// with io.ErrShortBuffer.
	Sign(sig, msg []byte, rand io.Reader) (n int, err error)
	// Zeroize wipes the key. SetKey must be called before reuse.
	Zeroize()
}

// The VerifySignature methods below are not inlined: TinyGo would inline all
// of them into the interface call, about 6 KiB more flash with all four.
var (
	_ SignatureVerifier = (*P256Verifier)(nil)
	_ SignatureVerifier = (*P384Verifier)(nil)
	_ SignatureVerifier = (*Ed25519Verifier)(nil)
	_ SignatureVerifier = (*RSAVerifier)(nil)
	_ KeySigner         = (*P256Signer)(nil)
	_ KeySigner         = (*P384Signer)(nil)
	_ KeySigner         = (*Ed25519Signer)(nil)
)

// P256Verifier verifies ECDSA P-256 signatures over SHA-256, SHA-384 or SHA-512.
// Its zero value is ready for use.
type P256Verifier struct {
	v ecdsa.P256Verifier
	d digests
}

// PublicKeyAlgorithm implements [SignatureVerifier].
func (*P256Verifier) PublicKeyAlgorithm() PublicKeyAlgorithm { return ECDSAP256 }

// VerifySignature implements [SignatureVerifier].
//
//go:noinline
func (p *P256Verifier) VerifySignature(key *Certificate, alg SignatureAlgorithm, msg, sig []byte) error {
	return p.v.VerifyASN1(key.PublicKey, p.d.sum(alg, msg), sig)
}

// P384Verifier verifies ECDSA P-384 signatures over SHA-256, SHA-384 or SHA-512.
// Its zero value is ready for use.
type P384Verifier struct {
	v ecdsa.P384Verifier
	d digests
}

// PublicKeyAlgorithm implements [SignatureVerifier].
func (*P384Verifier) PublicKeyAlgorithm() PublicKeyAlgorithm { return ECDSAP384 }

// VerifySignature implements [SignatureVerifier].
//
//go:noinline
func (p *P384Verifier) VerifySignature(key *Certificate, alg SignatureAlgorithm, msg, sig []byte) error {
	return p.v.VerifyASN1(key.PublicKey, p.d.sum(alg, msg), sig)
}

// Ed25519Verifier verifies Ed25519 signatures. Its zero value is ready for use.
type Ed25519Verifier struct {
	v ed25519.Verifier
}

// PublicKeyAlgorithm implements [SignatureVerifier].
func (*Ed25519Verifier) PublicKeyAlgorithm() PublicKeyAlgorithm { return Ed25519 }

// VerifySignature implements [SignatureVerifier].
//
//go:noinline
func (e *Ed25519Verifier) VerifySignature(key *Certificate, _ SignatureAlgorithm, msg, sig []byte) error {
	return e.v.Verify(key.PublicKey, msg, sig)
}

// RSAVerifier verifies RSA PKCS #1 v1.5 and PSS signatures over SHA-256,
// SHA-384 or SHA-512. Its zero value is ready for use.
type RSAVerifier struct {
	v rsa.Verifier
	d digests
}

// PublicKeyAlgorithm implements [SignatureVerifier].
func (*RSAVerifier) PublicKeyAlgorithm() PublicKeyAlgorithm { return RSA }

// VerifySignature implements [SignatureVerifier].
//
//go:noinline
func (r *RSAVerifier) VerifySignature(key *Certificate, alg SignatureAlgorithm, msg, sig []byte) error {
	h := rsa.SHA512
	switch alg {
	case SHA256WithRSA, SHA256WithRSAPSS:
		h = rsa.SHA256
	case SHA384WithRSA, SHA384WithRSAPSS:
		h = rsa.SHA384
	}
	digest := r.d.sum(alg, msg)
	switch alg {
	case SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		return r.v.VerifyPSS(key.PublicKey, key.RSAExponent, h, digest, sig)
	}
	return r.v.VerifyPKCS1v15(key.PublicKey, key.RSAExponent, h, digest, sig)
}

// P256Signer signs ecdsa_secp256r1_sha256. Its zero value has no key.
type P256Signer struct {
	s      ecdsa.P256Signer
	d      sha256.Digest
	digest [sha256.Size]byte
}

// PublicKeyAlgorithm implements [KeySigner].
func (*P256Signer) PublicKeyAlgorithm() PublicKeyAlgorithm { return ECDSAP256 }

// SetKey implements [KeySigner].
func (p *P256Signer) SetKey(d []byte) ([]byte, error) {
	if err := p.s.SetKey(d); err != nil {
		return nil, err
	}
	return p.s.PublicKey()
}

// Sign implements [KeySigner].
func (p *P256Signer) Sign(sig, msg []byte, rand io.Reader) (int, error) {
	p.d.Init()
	p.d.Write(msg)
	return p.s.SignASN1(sig, p.d.Sum(p.digest[:0]), rand)
}

// Zeroize implements [KeySigner].
func (p *P256Signer) Zeroize() {
	p.s.Zeroize()
	p.d = sha256.Digest{} // Zeroize panics on a never initialized Digest.
	clear(p.digest[:])
}

// P384Signer signs ecdsa_secp384r1_sha384. Its zero value has no key.
type P384Signer struct {
	s      ecdsa.P384Signer
	d      sha512.Digest
	digest [sha512.Size384]byte
}

// PublicKeyAlgorithm implements [KeySigner].
func (*P384Signer) PublicKeyAlgorithm() PublicKeyAlgorithm { return ECDSAP384 }

// SetKey implements [KeySigner].
func (p *P384Signer) SetKey(d []byte) ([]byte, error) {
	if err := p.s.SetKey(d); err != nil {
		return nil, err
	}
	return p.s.PublicKey()
}

// Sign implements [KeySigner].
func (p *P384Signer) Sign(sig, msg []byte, rand io.Reader) (int, error) {
	p.d.Init384()
	p.d.Write(msg)
	return p.s.SignASN1(sig, p.d.Sum(p.digest[:0]), rand)
}

// Zeroize implements [KeySigner].
func (p *P384Signer) Zeroize() {
	p.s.Zeroize()
	p.d = sha512.Digest{} // Zeroize panics on a never initialized Digest.
	clear(p.digest[:])
}

// Ed25519Signer signs ed25519 from the key's seed. Its zero value has no key.
type Ed25519Signer struct {
	s ed25519.Signer
}

// PublicKeyAlgorithm implements [KeySigner].
func (*Ed25519Signer) PublicKeyAlgorithm() PublicKeyAlgorithm { return Ed25519 }

// SetKey implements [KeySigner]. d is the seed.
func (e *Ed25519Signer) SetKey(d []byte) ([]byte, error) {
	if err := e.s.SetSeed(d); err != nil {
		return nil, err
	}
	return e.s.PublicKey()
}

// Sign implements [KeySigner]. Signatures are deterministic: rand is unused.
func (e *Ed25519Signer) Sign(sig, msg []byte, _ io.Reader) (int, error) {
	if len(sig) < ed25519.SignatureSize {
		return ed25519.SignatureSize, io.ErrShortBuffer
	}
	return ed25519.SignatureSize, e.s.Sign(sig, msg)
}

// Zeroize implements [KeySigner].
func (e *Ed25519Signer) Zeroize() { e.s.Zeroize() }

// digests hashes messages for the signature algorithms over SHA-2.
type digests struct {
	d256 sha256.Digest
	d512 sha512.Digest
	out  [64]byte
}

// sum returns the digest of msg that alg signs, in d.out. Not inlined: TinyGo
// would copy it into each SignatureVerifier at the interface call.
//
//go:noinline
func (d *digests) sum(alg SignatureAlgorithm, msg []byte) []byte {
	switch alg {
	case SHA256WithRSA, SHA256WithRSAPSS, ECDSAWithSHA256:
		d.d256.Init()
		d.d256.Write(msg)
		return d.d256.Sum(d.out[:0])
	case SHA384WithRSA, SHA384WithRSAPSS, ECDSAWithSHA384:
		d.d512.Init384()
	default:
		d.d512.Init()
	}
	d.d512.Write(msg)
	return d.d512.Sum(d.out[:0])
}
