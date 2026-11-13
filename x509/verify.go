package x509

import (
	"bytes"
	"cmp"
	"math/bits"
	"sync"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/rsa"
)

// RFC 8446 4.2.3 signature schemes accepted in CertificateVerify.
const (
	SchemeECDSAP256SHA256 = 0x0403 // ecdsa_secp256r1_sha256
	SchemeECDSAP384SHA384 = 0x0503 // ecdsa_secp384r1_sha384
	SchemeEd25519         = 0x0807 // ed25519
	SchemeRSAPSSSHA256    = 0x0804 // rsa_pss_rsae_sha256
	SchemeRSAPSSSHA384    = 0x0805 // rsa_pss_rsae_sha384
	SchemeRSAPSSSHA512    = 0x0806 // rsa_pss_rsae_sha512
)

const (
	// MaxChainLen is the longest chain a Verifier can build: leaf,
	// intermediates and root. It sizes the Verifier's working memory, and
	// bounds VerifierConfig.MaxChainLen.
	MaxChainLen = 8
	// DefaultMaxPeerCerts is VerifierConfig.MaxPeerCerts when zero.
	DefaultMaxPeerCerts = 16
	// DefaultMaxSignatureChecks is VerifierConfig.MaxSignatureChecks when
	// zero: crypto/x509's maxChainSignatureChecks.
	DefaultMaxSignatureChecks = 100
	// DefaultMinRSABits is VerifierConfig.MinRSABits when zero.
	DefaultMinRSABits = 2048
)

// Verifier implements [lcrypto.Verifier] with Go's crypto/x509 chain building
// and crypto/tls CertificateVerify checks, heap allocation free:
//
//   - The leaf must chain to one of the roots through the peer's intermediates,
//     every certificate within its validity period.
//   - Extended key usages are enforced down the chain as in crypto/x509.
//   - A server must be valid for the expected name, a DNS name or IP literal.
//   - The CertificateVerify signature must be the leaf key's under the scheme,
//     and the leaf's key usage, if present, must allow digital signatures.
//
// Certificates may carry RSA keys of MinRSABits (by default 2048) to 4096
// bits, ECDSA P-256 and P-384 keys and Ed25519 keys, and be signed with Ed25519
// or with PKCS #1 v1.5, PSS or ECDSA over SHA-256, SHA-384 or SHA-512, each
// as far as [VerifierConfig.Algorithms] lists a [SignatureVerifier] for the key.
// Chains needing an algorithm not listed, chains through CAs with name
// constraints, a policy constraint requiring explicit policy or a mapping of
// anyPolicy, and chains that need other curves, are rejected with
// [ErrUnsupported]. There is no revocation checking.
//
// The zero Verifier trusts nothing: call [Verifier.Configure] before use. A
// Verifier is safe for concurrent use: calls, Configure included, are
// serialized over its working memory. A Verifier is about 1.5 KiB on 32-bit
// platforms and 2.5 KiB on 64-bit ones, plus its Algorithms, from 3 KiB for
// [P256Verifier] to 9 KiB for [RSAVerifier]; declare them as package variables
// on devices with small stacks.
type Verifier struct {
	mu        sync.Mutex
	roots     lcrypto.CertChain
	nanotime  func() int64
	maxPeer   int
	maxChain  int
	maxChecks int
	minRSA    int
	algs      [MLDSA + 1]SignatureVerifier // Indexed by PublicKeyAlgorithm. nil is ErrUnsupported.
	sc        verifyScratch
}

// VerifierConfig configures a [Verifier]. The limits bound the work a peer can
// cause; zero selects the default. Memory does not depend on them.
type VerifierConfig struct {
	// Roots are the trust anchors as DER certificates. Each must parse. They
	// must not change while the Verifier uses them.
	Roots lcrypto.CertChain
	// Nanotime returns the wall-clock time in nanoseconds since the Unix
	// epoch, as time.Now().UnixNano(). It is required. Unlike the monotonic
	// Nanotime of lneto's tcp, it must be set from a real-time clock or NTP:
	// a clock counting from boot makes every certificate not yet valid.
	Nanotime func() int64
	// MaxPeerCerts is the most certificates a peer may present, by default
	// DefaultMaxPeerCerts.
	MaxPeerCerts int
	// MaxChainLen is the longest chain built, leaf through root, at most and
	// by default MaxChainLen.
	MaxChainLen int
	// MaxSignatureChecks is the most signatures checked while building one
	// chain, by default DefaultMaxSignatureChecks.
	// On microcontrollers a peer can make each check cost up to seconds: set
	// it near MaxChainLen, e.g. 8 to 16, as a valid chain needs one per link.
	MaxSignatureChecks int
	// MinRSABits is the smallest RSA modulus accepted, of the leaf and of
	// every signing key, from rsa.MinBits to rsa.MaxBits and by default
	// DefaultMinRSABits. crypto/x509 accepts 1024.
	MinRSABits int
	// Algorithms verify signatures, at most one per PublicKeyAlgorithm of
	// ECDSAP256, ECDSAP384, Ed25519 and RSA. At least one is required. They
	// must not be shared with another Verifier. Only the implementations a
	// program names are linked, so list what peers need, e.g. [P256Verifier].
	Algorithms []SignatureVerifier
}

// Configure checks cfg and makes v verify against it. Every root is parsed
// now, so a bad root fails here instead of in a handshake. On error v is left
// unconfigured.
func (v *Verifier) Configure(cfg VerifierConfig) error {
	v.mu.Lock()
	err := v.configure(cfg)
	if err != nil {
		v.roots = nil
		v.algs = [len(v.algs)]SignatureVerifier{}
	}
	v.mu.Unlock()
	return err
}

func (v *Verifier) configure(cfg VerifierConfig) error {
	if cfg.Roots == nil || cfg.Roots.NumCerts() == 0 {
		return errNoRoots
	}
	if cfg.Nanotime == nil {
		return errNoClock
	}
	if cfg.MaxPeerCerts < 0 || cfg.MaxChainLen < 0 || cfg.MaxChainLen > MaxChainLen || cfg.MaxSignatureChecks < 0 ||
		cfg.MinRSABits != 0 && (cfg.MinRSABits < rsa.MinBits || cfg.MinRSABits > rsa.MaxBits) {
		return errLimit
	}
	if len(cfg.Algorithms) == 0 {
		return errAlgorithms
	}
	v.algs = [len(v.algs)]SignatureVerifier{}
	for _, a := range cfg.Algorithms {
		if a == nil {
			return errAlgorithms
		}
		k := a.PublicKeyAlgorithm()
		switch k {
		case ECDSAP256, ECDSAP384, Ed25519, RSA:
		default:
			return errAlgorithms
		}
		if v.algs[k] != nil {
			return errAlgorithms
		}
		v.algs[k] = a
	}
	c := &v.sc.chain[0]
	for i := range cfg.Roots.NumCerts() {
		der, err := cfg.Roots.CertView(i)
		if err != nil {
			return errRootParse
		}
		if c.Parse(der) != nil {
			return errRootParse
		}
	}
	*c = Certificate{}
	v.roots, v.nanotime = cfg.Roots, cfg.Nanotime
	v.maxPeer = cmp.Or(cfg.MaxPeerCerts, DefaultMaxPeerCerts)
	v.maxChain = cmp.Or(cfg.MaxChainLen, MaxChainLen)
	v.maxChecks = cmp.Or(cfg.MaxSignatureChecks, DefaultMaxSignatureChecks)
	v.minRSA = cmp.Or(cfg.MinRSABits, DefaultMinRSABits)
	return nil
}

var _ lcrypto.Verifier = (*Verifier)(nil)

// Schemes appends to dst the RFC 8446 signature schemes the configured
// Algorithms verify, for the signature_algorithms extension: advertising one
// not verified lets a server pick a certificate that fails.
func (v *Verifier) Schemes(dst []uint16) []uint16 {
	v.mu.Lock()
	if v.algs[ECDSAP256] != nil {
		dst = append(dst, SchemeECDSAP256SHA256)
	}
	if v.algs[Ed25519] != nil {
		dst = append(dst, SchemeEd25519)
	}
	if v.algs[ECDSAP384] != nil {
		dst = append(dst, SchemeECDSAP384SHA384)
	}
	if v.algs[RSA] != nil {
		dst = append(dst, SchemeRSAPSSSHA256, SchemeRSAPSSSHA384, SchemeRSAPSSSHA512)
	}
	v.mu.Unlock()
	return dst
}

type verifyScratch struct {
	chain [MaxChainLen]Certificate // chain[0] is the leaf; chain[i+1] signs chain[i].
	next  [MaxChainLen]int         // Next candidate index to try as chain[i+1].
}

// VerifyPeer implements [lcrypto.Verifier].
func (v *Verifier) VerifyPeer(chainView lcrypto.CertChain, scheme uint16, peerIsServer bool, expectName, msg, sig []byte) error {
	if peerIsServer && len(expectName) == 0 {
		return errNoName
	}
	usage := ExtKeyUsageClientAuth
	if peerIsServer {
		usage = ExtKeyUsageServerAuth
	}
	v.mu.Lock() // No defer: TinyGo heap allocates deferred calls.
	err := v.verifyChain(chainView, usage, expectName)
	if err == nil {
		err = v.verifyCertificateVerify(&v.sc.chain[0], scheme, msg, sig)
	}
	v.mu.Unlock()
	return err
}

// VerifyChain checks chainView as VerifyPeer does, without a CertificateVerify
// signature: its leaf must chain to the roots, allow usage (any usage if usage
// has ExtKeyUsageAny) and be valid for name, a DNS name or IP literal, which
// must not be empty. [Verifier.VerifyChainAnyName] skips the name check.
func (v *Verifier) VerifyChain(chainView lcrypto.CertChain, usage ExtKeyUsage, name []byte) error {
	if len(name) == 0 {
		return errNoName
	}
	v.mu.Lock()
	err := v.verifyChain(chainView, usage, name)
	v.mu.Unlock()
	return err
}

// VerifyChainAnyName is VerifyChain accepting the leaf whatever names it is
// valid for: whoever holds its key is authenticated as any of them. Use it
// only where the caller checks the identity itself, i.e. of a TLS client.
func (v *Verifier) VerifyChainAnyName(chainView lcrypto.CertChain, usage ExtKeyUsage) error {
	v.mu.Lock()
	err := v.verifyChain(chainView, usage, nil)
	v.mu.Unlock()
	return err
}

func (v *Verifier) verifyChain(chainView lcrypto.CertChain, usage ExtKeyUsage, name []byte) error {
	if v.roots == nil {
		return errNotConfigured
	}
	nPeer := chainView.NumCerts()
	if nPeer <= 0 {
		return errNoCerts
	} else if nPeer > v.maxPeer {
		return errChainLen
	}
	ns := v.nanotime()
	now, frac := ns/1e9, ns%1e9
	if frac < 0 { // Before 1970: floor to the second.
		now--
	}
	nowFrac := frac != 0

	leaf := &v.sc.chain[0]
	der, err := chainView.CertView(0)
	if err != nil {
		return errCertView
	}
	if err := leaf.Parse(der); err != nil {
		return err
	}
	if err := checkValid(leaf, now, nowFrac); err != nil {
		return err
	}
	// RFC 8446 4.4.2.2 and RFC 5280 4.2.1.3: the leaf key signs, so a key usage
	// extension must allow it. crypto/x509 does not check the leaf's.
	if leaf.KeyUsage != 0 && leaf.KeyUsage&KeyUsageDigitalSignature == 0 {
		return errLeafKeyUsage
	}
	if leaf.PublicKeyAlgorithm == RSA && rsaBits(leaf.PublicKey) < v.minRSA {
		return errWeakRSA
	}
	if len(name) > 0 {
		if err := leaf.VerifyHostname(name); err != nil {
			return err
		}
	}
	return v.buildChain(chainView, nPeer, now, nowFrac, usage)
}

// verifyCertificateVerify checks sig is the leaf key's signature of msg as
// crypto/tls verifyHandshakeSignature does for TLS 1.3.
func (v *Verifier) verifyCertificateVerify(leaf *Certificate, scheme uint16, msg, sig []byte) error {
	err := v.certificateVerify(leaf, scheme, msg, sig)
	if err != nil && err != ErrScheme && err != ErrUnsupported {
		err = errCertificateVerify // The signature packages' errors map to no alert.
	}
	return err
}

func (v *Verifier) certificateVerify(leaf *Certificate, scheme uint16, msg, sig []byte) error {
	var key PublicKeyAlgorithm
	var alg SignatureAlgorithm
	switch scheme {
	case SchemeECDSAP256SHA256:
		key, alg = ECDSAP256, ECDSAWithSHA256
	case SchemeECDSAP384SHA384:
		key, alg = ECDSAP384, ECDSAWithSHA384
	case SchemeEd25519:
		key, alg = Ed25519, PureEd25519
	case SchemeRSAPSSSHA256:
		key, alg = RSA, SHA256WithRSAPSS
	case SchemeRSAPSSSHA384:
		key, alg = RSA, SHA384WithRSAPSS
	case SchemeRSAPSSSHA512:
		key, alg = RSA, SHA512WithRSAPSS
	default:
		return ErrScheme
	}
	if leaf.PublicKeyAlgorithm != key {
		return ErrScheme
	}
	return v.verifySignature(leaf, alg, msg, sig)
}

// verifySignature checks sig is key's signature of msg under alg with the
// configured Algorithms, after the checks no SignatureVerifier is trusted with.
func (v *Verifier) verifySignature(key *Certificate, alg SignatureAlgorithm, msg, sig []byte) error {
	k := key.PublicKeyAlgorithm
	switch alg {
	case PureEd25519:
		if k != Ed25519 {
			return errKeyMismatch
		}
	case ECDSAWithSHA256, ECDSAWithSHA384, ECDSAWithSHA512:
		switch k {
		case ECDSAP224, ECDSAP521:
			return ErrUnsupported
		case ECDSAP256, ECDSAP384:
		default:
			return errKeyMismatch
		}
	case SHA256WithRSA, SHA384WithRSA, SHA512WithRSA, SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		if k != RSA {
			return errKeyMismatch
		}
		if rsaBits(key.PublicKey) < v.minRSA {
			return errWeakRSA
		}
	default:
		return errSignatureAlgorithm
	}
	sv := v.algs[k] // k is ECDSAP256, ECDSAP384, Ed25519 or RSA: in range.
	if sv == nil {
		return ErrUnsupported
	}
	return sv.VerifySignature(key, alg, msg, sig)
}

// checkValid is isValid's checks on c alone.
func checkValid(c *Certificate, now int64, nowFrac bool) error {
	if c.UnhandledCriticalExtension {
		return errUnhandledCritical
	}
	if now < c.NotBefore {
		return ErrNotYetValid
	}
	if now > c.NotAfter || now == c.NotAfter && nowFrac {
		return ErrExpired
	}
	return nil
}

// buildChain searches depth first for a chain from sc.chain[0] to a root, as
// crypto/x509 buildChains does, trying roots before intermediates, and accepts
// the first chain that also passes the checks crypto/x509 Verify applies to
// whole chains.
func (v *Verifier) buildChain(peer lcrypto.CertChain, nPeer int, now int64, nowFrac bool, usage ExtKeyUsage) error {
	sc := &v.sc
	nRoots := v.roots.NumCerts()
	// Verify: a leaf that is itself a root is a chain of one.
	for i := 0; i < nRoots; i++ {
		der, err := v.roots.CertView(i)
		if err == nil && bytes.Equal(der, sc.chain[0].Raw) {
			if !chainUsageOK(sc.chain[:1], usage) {
				return ErrIncompatibleUsage
			}
			return nil
		}
	}
	// Candidates are the roots, then peer certificates 1 onwards, each pool
	// visited once per key ID tier: sc.next counts visits up to 3*nCandidates.
	nCandidates := nRoots + nPeer - 1
	// hint is the first reason a candidate was rejected, as crypto/x509
	// reports. chainErr is why a complete chain was: it takes precedence, and
	// ErrUnsupported over ErrIncompatibleUsage since crypto/x509 may accept
	// the unsupported chain.
	var hint, chainErr error
	checks := 0
	depth := 0 // sc.chain[:depth+1] is the chain so far.
	sc.next[0] = 0
	for depth >= 0 {
		if depth+1 == v.maxChain || sc.next[depth] >= 3*nCandidates {
			depth-- // Exhausted: backtrack.
			continue
		}
		visit := sc.next[depth]
		sc.next[depth]++
		var idx, tier int
		if visit < 3*nRoots {
			tier, idx = visit/nRoots, visit%nRoots
		} else {
			visit -= 3 * nRoots
			tier, idx = visit/(nPeer-1), nRoots+visit%(nPeer-1)
		}
		isRoot := idx < nRoots
		var der []byte
		var err error
		if isRoot {
			der, err = v.roots.CertView(idx)
		} else {
			der, err = peer.CertView(idx - nRoots + 1)
		}
		child, cand := &sc.chain[depth], &sc.chain[depth+1]
		// findPotentialParents: skip what is not the issuer or does not parse.
		// The subject alone is read first: a full parse costs about 20 times more.
		if err != nil || !bytes.Equal(child.RawIssuer, rawSubject(der)) || cand.Parse(der) != nil ||
			keyIDTier(child, cand) != tier {
			continue
		}
		checks++
		if checks > v.maxChecks {
			return errSignatureLimit
		}
		if alreadyInChain(cand, sc.chain[:depth+1]) {
			continue
		}
		err = v.checkSignatureFrom(child, cand)
		if err == nil {
			err = checkValid(cand, now, nowFrac)
		}
		if err == nil && !isRoot && (!cand.BasicConstraintsValid || !cand.IsCA) {
			err = errNotAuthorized
		}
		if err == nil && cand.BasicConstraintsValid && cand.MaxPathLen >= 0 && depth > cand.MaxPathLen {
			err = errTooManyIntermediates // depth is the number of intermediates below cand.
		}
		if err != nil {
			if hint == nil {
				hint = err
			}
			continue
		}
		if !isRoot {
			depth++
			sc.next[depth] = 0
			continue
		}
		chain := sc.chain[:depth+2]
		switch {
		case !chainSupported(chain):
			chainErr = ErrUnsupported
		case !chainUsageOK(chain, usage):
			if chainErr == nil {
				chainErr = ErrIncompatibleUsage
			}
		default:
			return nil
		}
	}
	switch {
	case chainErr != nil:
		return chainErr
	case hint != nil:
		return hint
	}
	return ErrUnknownAuthority
}

// keyIDTier is the order in which crypto/x509's findPotentialParents tries
// parent: 0 if its subject key ID is child's authority key ID, 1 if only one of
// them is present, and 2 if they differ.
func keyIDTier(child, parent *Certificate) int {
	switch {
	case bytes.Equal(parent.SubjectKeyId, child.AuthorityKeyId):
		return 0
	case len(parent.SubjectKeyId) == 0 || len(child.AuthorityKeyId) == 0:
		return 1
	}
	return 2
}

// alreadyInChain is crypto/x509's: equal subject, public key and SAN.
func alreadyInChain(cand *Certificate, chain []Certificate) bool {
	for i := range chain {
		c := &chain[i]
		if bytes.Equal(cand.RawSubject, c.RawSubject) &&
			bytes.Equal(cand.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) &&
			(cand.SubjectAltName == nil) == (c.SubjectAltName == nil) &&
			bytes.Equal(cand.SubjectAltName, c.SubjectAltName) {
			return true
		}
	}
	return false
}

// chainSupported rejects chains needing name constraint or policy processing
// that crypto/x509 does and this package does not: crypto/x509 may accept
// them. CA name constraints apply to the certificates below, so the leaf's do
// not matter, and neither does a policy mapping by the leaf.
func chainSupported(chain []Certificate) bool {
	if chain[0].RequireExplicitPolicy {
		return false
	}
	for i := 1; i < len(chain); i++ {
		c := &chain[i]
		if c.NameConstraints || c.RequireExplicitPolicy || c.MapsAnyPolicy {
			return false
		}
	}
	return true
}

// chainUsageOK is checkChainForKeyUsage for a single requested usage.
func chainUsageOK(chain []Certificate, usage ExtKeyUsage) bool {
	if usage&ExtKeyUsageAny != 0 {
		return true
	}
	for i := range chain {
		eku := chain[i].ExtKeyUsage
		if eku != 0 && eku&(ExtKeyUsageAny|usage) == 0 {
			return false
		}
	}
	return true
}

// checkSignatureFrom is crypto/x509's CheckSignatureFrom.
func (v *Verifier) checkSignatureFrom(c, parent *Certificate) error {
	err := v.checkSignature(c, parent)
	if _, ours := err.(errX509); err != nil && !ours {
		err = errCertSignature // The signature packages' errors map to no alert.
	}
	return err
}

func (v *Verifier) checkSignature(c, parent *Certificate) error {
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return errConstraint
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return errConstraint
	}
	return v.verifySignature(parent, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// rsaBits is the bit length of big-endian modulus n.
func rsaBits(n []byte) int {
	for len(n) > 0 && n[0] == 0 {
		n = n[1:]
	}
	if len(n) == 0 {
		return 0
	}
	return 8*(len(n)-1) + bits.Len8(n[0])
}
