package x509

import (
	"bytes"
	"io"
	"sync"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/ed25519"
	"github.com/soypat/lcrypto/internal/std/cryptobyte"
	"github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"
)

// Credential implements [lcrypto.Credential] with an ECDSA P-256 or P-384 key
// or an Ed25519 key, signing TLS 1.3 CertificateVerify with
// ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 or ed25519 through the
// [KeySigner] configured for the key, without allocating.
//
// The zero Credential has no key: call [Credential.Configure]. A Credential is
// safe for concurrent use: calls, Configure included, are serialized over its
// working memory, about 0.3 KiB plus its Signers, 4 to 6 KiB each.
type Credential struct {
	mu     sync.Mutex
	rand   io.Reader
	chain  lcrypto.CertChain
	scheme uint16
	signer KeySigner   // The configured key's; nil when unkeyed.
	leaf   Certificate // Scratch of Configure.
}

var _ lcrypto.Credential = (*Credential)(nil)

// CredentialConfig configures a [Credential].
type CredentialConfig struct {
	// Chain is the certificate chain, leaf first. It must not change while
	// the Credential uses it.
	Chain lcrypto.CertChain
	// Key is the leaf's private key: a PKCS #8 PrivateKeyInfo or SEC 1
	// ECPrivateKey, as crypto/x509's ParsePKCS8PrivateKey and
	// ParseECPrivateKey read them. It is not retained; wipe it after.
	Key []byte
	// Rand is the entropy of hedged ECDSA signatures. If nil, signatures are
	// deterministic per RFC 6979: secure without any entropy source, as the
	// nonce derives from the key and message. With Rand, a broken entropy
	// source still does not leak the key. Ed25519 signatures are always
	// deterministic.
	Rand io.Reader
	// Signers sign with the leaf key: Configure uses the one for its
	// PublicKeyAlgorithm, of ECDSAP256, ECDSAP384 and Ed25519. At least one is
	// required. They must not be shared with another Credential.
	Signers []KeySigner
}

// Configure installs cfg's chain and key, failing if the key is not the leaf
// certificate's. On error c is left without a key.
func (c *Credential) Configure(cfg CredentialConfig) error {
	c.mu.Lock()
	err := c.configure(cfg.Chain, cfg.Key, cfg.Signers)
	c.leaf = Certificate{}
	if err != nil {
		c.zeroize()
	} else {
		c.rand = cfg.Rand
	}
	c.mu.Unlock()
	return err
}

func (c *Credential) configure(chain lcrypto.CertChain, keyDER []byte, signers []KeySigner) error {
	c.zeroize()
	if len(signers) == 0 {
		return errSigners
	}
	var seen [MLDSA + 1]bool
	for _, s := range signers {
		if s == nil {
			return errSigners
		}
		k := s.PublicKeyAlgorithm()
		switch k {
		case ECDSAP256, ECDSAP384, Ed25519:
		default:
			return errSigners
		}
		if seen[k] {
			return errSigners
		}
		seen[k] = true
	}
	if chain == nil || chain.NumCerts() == 0 {
		return errNoCerts
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
	var scheme uint16
	switch c.leaf.PublicKeyAlgorithm {
	case Ed25519:
		if !bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		scheme = SchemeEd25519
	case ECDSAP256:
		if curve != nil && !bytes.Equal(curve, oidCurveP256) || bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		d, err = fitKey(d, 32)
		scheme = SchemeECDSAP256SHA256
	case ECDSAP384:
		if curve != nil && !bytes.Equal(curve, oidCurveP384) || bytes.Equal(curve, oidPublicKeyEd25519) {
			return errKeyCurve
		}
		d, err = fitKey(d, 48)
		scheme = SchemeECDSAP384SHA384
	}
	if err != nil {
		return err
	}
	var signer KeySigner
	for _, s := range signers {
		if s.PublicKeyAlgorithm() == c.leaf.PublicKeyAlgorithm {
			signer = s
		}
	}
	if signer == nil {
		return errLeafKey
	}
	c.signer = signer // Set first so zeroize wipes a key that does not match.
	pub, err := signer.SetKey(d)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, c.leaf.PublicKey) {
		return errKeyPublic
	}
	c.chain, c.scheme = chain, scheme
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
	return c.signer.Sign(sig, msg, c.rand)
}

// Zeroize wipes the private key; Configure must be called before reuse.
func (c *Credential) Zeroize() {
	c.mu.Lock()
	c.zeroize()
	c.mu.Unlock()
}

func (c *Credential) zeroize() {
	c.chain, c.scheme, c.rand = nil, 0, nil
	if c.signer != nil {
		c.signer.Zeroize()
		c.signer = nil
	}
}

// NumCerts implements [lcrypto.CertChain].
func (c *Credential) NumCerts() int {
	c.mu.Lock()
	n := 0
	if c.chain != nil {
		n = c.chain.NumCerts()
	}
	c.mu.Unlock()
	return n
}

// Cert implements [lcrypto.CertChain].
func (c *Credential) Cert(dst []byte, i int) (int, error) {
	c.mu.Lock()
	var n int
	var err error = errNoCredential
	if c.chain != nil {
		n, err = c.chain.Cert(dst, i)
	}
	c.mu.Unlock()
	return n, err
}

// CertView implements [lcrypto.CertChain]. The view is of the configured chain,
// which outlives a later Configure or Zeroize of c.
func (c *Credential) CertView(i int) ([]byte, error) {
	c.mu.Lock()
	var view []byte
	var err error = errNoCredential
	if c.chain != nil {
		view, err = c.chain.CertView(i)
	}
	c.mu.Unlock()
	return view, err
}
