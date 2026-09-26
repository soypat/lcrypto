package x509

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/ed25519"
	"github.com/soypat/lcrypto/internal/std/cryptobyte"
	"github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/sha512"
)

var (
	errKeyDER       = errors.New("x509: failed to parse EC private key")
	errKeyCurve     = errors.New("x509: private key curve does not match the certificate")
	errKeyPublic    = errors.New("x509: private key does not match the certificate public key")
	errLeafKey      = errors.New("x509: certificate key is not ECDSA P-256, P-384 or Ed25519")
	errNoCredential = errors.New("x509: Credential has no key")
	errSignScheme   = errors.New("x509: signature scheme not offered by the Credential")
)

// Credential implements [lcrypto.Credential] with an ECDSA P-256 or P-384 key
// or an Ed25519 key, signing TLS 1.3 CertificateVerify with
// ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 or ed25519 as crypto/ecdsa and
// crypto/ed25519 do, without allocating.
//
// The zero Credential has no key: call SetKey. A Credential is safe for
// concurrent use: calls are serialized over its working memory, about 15 KiB.
type Credential struct {
	// Rand is the entropy of hedged ECDSA signatures. If nil, signatures are
	// deterministic per RFC 6979: secure without any entropy source, as the
	// nonce derives from the key and message. With Rand, a broken entropy
	// source still does not leak the key. Ed25519 signatures are always
	// deterministic. Set before first use.
	Rand io.Reader

	mu     sync.Mutex
	chain  lcrypto.CertChain
	scheme uint16
	p256   ecdsa.P256Signer
	p384   ecdsa.P384Signer
	ed     ed25519.Signer
	d256   sha256.Digest
	d512   sha512.Digest
	digest [64]byte
	leaf   Certificate // Scratch of SetKey.
}

var _ lcrypto.Credential = (*Credential)(nil)

// SetKey installs chain, leaf first, and the private key of its leaf. keyDER is
// a PKCS #8 PrivateKeyInfo or SEC 1 ECPrivateKey, as crypto/x509's
// ParsePKCS8PrivateKey and ParseECPrivateKey read them. SetKey fails if the key
// is not the leaf certificate's. Chain must remain valid while c is in use.
func (c *Credential) SetKey(chain lcrypto.CertChain, keyDER []byte) error {
	c.mu.Lock()
	err := c.setKey(chain, keyDER)
	c.leaf = Certificate{}
	if err != nil {
		c.zeroize()
	}
	c.mu.Unlock()
	return err
}

func (c *Credential) setKey(chain lcrypto.CertChain, keyDER []byte) error {
	c.zeroize()
	if chain == nil || chain.NumCerts() == 0 {
		return errChainLen
	}
	der, err := chain.CertView(0)
	if err != nil {
		return err
	}
	if err := c.leaf.Parse(der); err != nil {
		return err
	}
	d, curve, err := parseECPrivateKey(keyDER)
	if err != nil {
		return err
	}
	var pub []byte
	switch c.leaf.PublicKeyAlgorithm {
	case Ed25519:
		if !bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		if err = c.ed.SetSeed(d); err == nil {
			pub, err = c.ed.PublicKey()
		}
		c.scheme = SchemeEd25519
	case ECDSAP256:
		if curve != nil && !bytes.Equal(curve, oidCurveP256) || bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		if d, err = fitKey(d, 32); err == nil {
			err = c.p256.SetKey(d)
		}
		if err == nil {
			pub, err = c.p256.PublicKey()
		}
		c.scheme = SchemeECDSAP256SHA256
	case ECDSAP384:
		if curve != nil && !bytes.Equal(curve, oidCurveP384) || bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		if d, err = fitKey(d, 48); err == nil {
			err = c.p384.SetKey(d)
		}
		if err == nil {
			pub, err = c.p384.PublicKey()
		}
		c.scheme = SchemeECDSAP384SHA384
	default:
		return errLeafKey
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, c.leaf.PublicKey) {
		return errKeyPublic
	}
	c.chain = chain
	return nil
}

// fitKey strips the leading zero padding some encoders add, as crypto/x509 does.
func fitKey(d []byte, size int) ([]byte, error) {
	for len(d) > size {
		if d[0] != 0 {
			return nil, errKeyDER
		}
		d = d[1:]
	}
	return d, nil
}

// parseECPrivateKey returns the private key octets and the named curve OID, if
// any, of a PKCS #8 or SEC 1 key. For PKCS #8 the curve is the algorithm's; an
// Ed25519 PKCS #8 key has the Ed25519 OID as curve and its seed as key.
//
//	PrivateKeyInfo ::= SEQUENCE {
//	  version INTEGER, algorithm AlgorithmIdentifier, privateKey OCTET STRING, ... }
//	ECPrivateKey ::= SEQUENCE {
//	  version INTEGER (1), privateKey OCTET STRING,
//	  parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
func parseECPrivateKey(der cryptobyte.String) (d, curve []byte, err error) {
	var seq cryptobyte.String
	var version int
	if !der.ReadASN1(&seq, asn1.SEQUENCE) || !der.Empty() || !seq.ReadASN1Int(&version) {
		return nil, nil, errKeyDER
	}
	if seq.PeekASN1Tag(asn1.SEQUENCE) { // PKCS #8.
		var ai, inner cryptobyte.String
		var alg []byte
		if version != 0 && version != 1 ||
			!seq.ReadASN1(&ai, asn1.SEQUENCE) || !ai.ReadASN1ObjectIdentifierBytes(&alg) ||
			!seq.ReadASN1(&inner, asn1.OCTET_STRING) {
			return nil, nil, errKeyDER
		}
		if bytes.Equal(alg, oidPublicKeyEd25519) {
			// RFC 8410: parameters absent, CurvePrivateKey ::= OCTET STRING.
			if !ai.Empty() || !inner.ReadASN1((*cryptobyte.String)(&d), asn1.OCTET_STRING) ||
				!inner.Empty() || len(d) != ed25519.SeedSize {
				return nil, nil, errKeyDER
			}
			return d, oidPublicKeyEd25519, nil
		}
		if !bytes.Equal(alg, oidPublicKeyECDSA) || !ai.ReadASN1ObjectIdentifierBytes(&curve) || !ai.Empty() {
			return nil, nil, errKeyDER
		}
		d, _, err = parseECPrivateKey(inner)
		return d, curve, err
	}
	var params cryptobyte.String
	var hasParams bool
	if version != 1 || !seq.ReadASN1((*cryptobyte.String)(&d), asn1.OCTET_STRING) ||
		!seq.ReadOptionalASN1(&params, &hasParams, asn1.Tag(0).Constructed().ContextSpecific()) ||
		!seq.SkipOptionalASN1(asn1.Tag(1).Constructed().ContextSpecific()) || !seq.Empty() {
		return nil, nil, errKeyDER
	}
	if hasParams && (!params.ReadASN1ObjectIdentifierBytes(&curve) || !params.Empty()) {
		return nil, nil, errKeyDER
	}
	return d, curve, nil
}

// Scheme implements [lcrypto.Credential]: the Credential's one scheme if offered.
func (c *Credential) Scheme(offered []uint16) uint16 {
	c.mu.Lock()
	scheme := c.scheme
	c.mu.Unlock()
	for _, s := range offered {
		if s == scheme && s != 0 {
			return s
		}
	}
	return 0
}

// Sign implements [lcrypto.Credential]. If sig is too short it writes nothing
// and returns the length needed with [io.ErrShortBuffer];
// [ecdsa.P384SignatureMaxSize] always suffices.
func (c *Credential) Sign(sig, msg []byte, selectedScheme uint16) (int, error) {
	c.mu.Lock()
	n, err := c.sign(sig, msg, selectedScheme)
	c.mu.Unlock()
	return n, err
}

func (c *Credential) sign(sig, msg []byte, scheme uint16) (int, error) {
	if c.scheme == 0 {
		return 0, errNoCredential
	}
	if scheme != c.scheme {
		return 0, errSignScheme
	}
	if scheme == SchemeEd25519 {
		if len(sig) < ed25519.SignatureSize {
			return ed25519.SignatureSize, io.ErrShortBuffer
		}
		return ed25519.SignatureSize, c.ed.Sign(sig, msg)
	}
	if scheme == SchemeECDSAP256SHA256 {
		c.d256.Init()
		c.d256.Write(msg)
		return c.p256.SignASN1(sig, c.d256.Sum(c.digest[:0]), c.Rand)
	}
	c.d512.Init384()
	c.d512.Write(msg)
	return c.p384.SignASN1(sig, c.d512.Sum(c.digest[:0]), c.Rand)
}

// Zeroize wipes the private key; SetKey must be called before reuse.
func (c *Credential) Zeroize() {
	c.mu.Lock()
	c.zeroize()
	c.mu.Unlock()
}

func (c *Credential) zeroize() {
	c.chain, c.scheme = nil, 0
	c.p256.Zeroize()
	c.p384.Zeroize()
	c.ed.Zeroize()
	c.d256 = sha256.Digest{} // Zeroize panics on a never initialized SHA-512 Digest.
	c.d512 = sha512.Digest{}
	clear(c.digest[:])
}

// NumCerts implements [lcrypto.CertChain].
func (c *Credential) NumCerts() int {
	if c.chain == nil {
		return 0
	}
	return c.chain.NumCerts()
}

// Cert implements [lcrypto.CertChain].
func (c *Credential) Cert(dst []byte, i int) (int, error) {
	if c.chain == nil {
		return 0, errNoCredential
	}
	return c.chain.Cert(dst, i)
}

// CertView implements [lcrypto.CertChain].
func (c *Credential) CertView(i int) ([]byte, error) {
	if c.chain == nil {
		return nil, errNoCredential
	}
	return c.chain.CertView(i)
}
