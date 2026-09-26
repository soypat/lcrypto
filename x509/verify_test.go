package x509_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/soypat/lcrypto"
	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

type chainCase struct {
	name        string
	roots       []*lt.Cert
	chain       []*lt.Cert // Leaf first, as sent by the peer.
	host        string
	usage       lx509.ExtKeyUsage // Zero: server authentication.
	since       string            // Go release whose crypto/x509 decides as wantErr, if newer than go1.26.
	at          time.Time         // Zero: lt.Epoch.
	wantErr     bool              // crypto/x509's verdict, checked to keep cases meaningful.
	unsupported bool              // crypto/x509 accepts; Verifier fails closed with ErrUnsupported.
	stricter    bool              // crypto/x509 accepts; a stricter Verifier policy rejects.
}

// pki issues test certificates, all signed by the one that issued the previous.
type pki struct {
	t    *testing.T
	nRSA int
}

func (p *pki) key(kind string) crypto.Signer {
	switch kind {
	case "rsa":
		p.nRSA++
		return lt.RSAKey(p.t, 2048, p.nRSA-1)
	case "rsa1024":
		return lt.RSAKey(p.t, 1024, 0)
	case "rsa4096":
		return lt.RSAKey(p.t, 4096, 0)
	case "p384":
		return lt.ECKey(p.t, elliptic.P384())
	case "ed25519":
		return lt.Ed25519Key(p.t)
	case "p521":
		return lt.ECKey(p.t, elliptic.P521())
	}
	return lt.ECKey(p.t, elliptic.P256())
}

// issue makes a certificate for a new key of kind, signed by parent (self-signed
// if nil), after edit changes its template.
func (p *pki) issue(kind, cn string, isCA bool, parent *lt.Cert, edit func(*x509.Certificate)) *lt.Cert {
	tmpl := lt.Template(cn, isCA)
	if !isCA {
		tmpl.DNSNames = []string{"example.com", "*.wild.example.com"}
		tmpl.IPAddresses = []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1")}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if edit != nil {
		edit(tmpl)
	}
	return lt.NewCert(p.t, tmpl, p.key(kind), parent)
}

func certs(c ...*lt.Cert) []*lt.Cert { return c }

func ders(c []*lt.Cert) lt.Chain {
	out := make(lt.Chain, len(c))
	for i := range c {
		out[i] = c[i].DER
	}
	return out
}

func stdUsage(u lx509.ExtKeyUsage) x509.ExtKeyUsage {
	switch u {
	case lx509.ExtKeyUsageAny:
		return x509.ExtKeyUsageAny
	case lx509.ExtKeyUsageClientAuth:
		return x509.ExtKeyUsageClientAuth
	}
	return x509.ExtKeyUsageServerAuth
}

// RFC 8446 6.2 alert descriptions of Verifier errors.
const (
	alertBadCertificate         = 42
	alertUnsupportedCertificate = 43
	alertCertificateExpired     = 45
	alertIllegalParameter       = 47
	alertUnknownCA              = 48
	alertDecryptError           = 51
	alertInternalError          = 80
	alertCertificateRequired    = 116
)

// alertOf fails t unless err, returned by Verifier, carries a TLS alert.
func alertOf(t testing.TB, err error) uint8 {
	t.Helper()
	a, ok := err.(interface{ Alert() uint8 })
	if !ok {
		t.Fatalf("%v (%T) carries no TLS alert", err, err)
	}
	return a.Alert()
}

// newVerifier returns a Verifier configured with roots at time at, and limits of cfg.
func newVerifier(t testing.TB, roots lcrypto.CertChain, at time.Time, cfg lx509.VerifierConfig) *lx509.Verifier {
	t.Helper()
	cfg.Roots, cfg.Nanotime = roots, func() int64 { return at.UnixNano() }
	v := new(lx509.Verifier)
	if err := v.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	return v
}

func stdVerify(roots, chain lt.Chain, host string, usage x509.ExtKeyUsage, at time.Time) error {
	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}
	for _, der := range roots {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		opts.Roots.AddCert(c)
	}
	for _, der := range chain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		opts.Intermediates.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	_, err = leaf.Verify(opts)
	return err
}

func TestVerifyChain(t *testing.T) {
	p := &pki{t: t}
	rootEC := p.issue("ec", "root EC", true, nil, nil)
	interEC := p.issue("ec", "inter EC", true, rootEC, nil)
	leafEC := p.issue("ec", "leaf EC", false, interEC, nil)
	rootRSA := p.issue("rsa", "root RSA", true, nil, nil)
	interRSA := p.issue("rsa", "inter RSA", true, rootRSA, nil)
	leafRSA := p.issue("rsa", "leaf RSA", false, interRSA, nil)
	pss := func(alg x509.SignatureAlgorithm) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.SignatureAlgorithm = alg }
	}
	rootPSS := p.issue("rsa", "root PSS", true, nil, pss(x509.SHA512WithRSAPSS))
	interPSS := p.issue("rsa", "inter PSS", true, rootPSS, pss(x509.SHA384WithRSAPSS))
	leafPSS := p.issue("ec", "leaf PSS", false, interPSS, pss(x509.SHA256WithRSAPSS))
	interMixed := p.issue("ec", "inter mixed", true, rootRSA, pss(x509.SHA512WithRSA))
	leafMixed := p.issue("rsa", "leaf mixed", false, interMixed, pss(x509.ECDSAWithSHA384))
	root1024 := p.issue("rsa1024", "root 1024", true, nil, nil)
	leaf4096 := p.issue("rsa4096", "leaf 4096", false, root1024, pss(x509.SHA384WithRSA))
	selfSigned := p.issue("ec", "self", false, nil, nil)
	root384 := p.issue("p384", "root P-384", true, nil, nil)
	leaf384 := p.issue("ec", "leaf under P-384", false, root384, nil)
	leafOf384 := p.issue("p384", "leaf P-384", false, rootEC, nil)
	inter384 := p.issue("p384", "inter P-384", true, rootRSA, pss(x509.SHA256WithRSA))
	leafOfInter384 := p.issue("ec", "leaf under P-384 inter", false, inter384, pss(x509.ECDSAWithSHA384))
	leafOfInter384SHA512 := p.issue("ec", "leaf under P-384 SHA-512", false, inter384, pss(x509.ECDSAWithSHA512))
	rootEd := p.issue("ed25519", "root Ed25519", true, nil, nil)
	interEd := p.issue("ed25519", "inter Ed25519", true, rootEd, nil)
	leafOfEd := p.issue("ec", "leaf under Ed25519", false, interEd, nil)
	root521 := p.issue("p521", "root P-521", true, nil, nil)
	leaf521 := p.issue("ec", "leaf under P-521", false, root521, nil)

	expired := p.issue("ec", "expired", false, interEC, func(c *x509.Certificate) {
		c.NotAfter = lt.Epoch.Add(-time.Second)
	})
	notYet := p.issue("ec", "not yet", false, interEC, func(c *x509.Certificate) {
		c.NotBefore = lt.Epoch.Add(time.Second)
	})
	interExpired := p.issue("ec", "inter expired", true, rootEC, func(c *x509.Certificate) {
		c.NotAfter = lt.Epoch.Add(-time.Hour)
	})
	leafOfExpired := p.issue("ec", "leaf of expired", false, interExpired, nil)
	interNotCA := p.issue("ec", "inter not CA", false, rootEC, func(c *x509.Certificate) {
		c.KeyUsage |= x509.KeyUsageCertSign
		c.ExtKeyUsage = nil
	})
	leafOfNotCA := p.issue("ec", "leaf of not CA", false, interNotCA, nil)
	interNoBC := p.issue("ec", "inter no basic constraints", true, rootEC, func(c *x509.Certificate) {
		c.BasicConstraintsValid = false
	})
	leafOfNoBC := p.issue("ec", "leaf of no BC", false, interNoBC, nil)
	interNoCertSign := p.issue("ec", "inter no certSign", true, rootEC, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature
	})
	leafOfNoCertSign := p.issue("ec", "leaf of no certSign", false, interNoCertSign, nil)
	interLen0 := p.issue("ec", "inter pathlen 0", true, rootEC, func(c *x509.Certificate) {
		c.MaxPathLen, c.MaxPathLenZero = 0, true
	})
	inter2 := p.issue("ec", "inter under pathlen 0", true, interLen0, nil)
	leafOfInter2 := p.issue("ec", "leaf 2 deep", false, inter2, nil)
	leafOfLen0 := p.issue("ec", "leaf of pathlen 0", false, interLen0, nil)
	clientOnly := p.issue("ec", "client only", false, interEC, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	anyEKU := p.issue("ec", "any EKU", false, interEC, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	})
	noEKU := p.issue("ec", "no EKU", false, interEC, func(c *x509.Certificate) { c.ExtKeyUsage = nil })
	kuNoSign := p.issue("ec", "KU without digitalSignature", false, interEC, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyAgreement
	})
	kuSign := p.issue("ec", "KU with digitalSignature", false, interEC, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	})
	noKU := p.issue("ec", "no KU", false, interEC, func(c *x509.Certificate) { c.KeyUsage = 0 })
	leaf1024 := p.issue("rsa1024", "leaf RSA-1024", false, interRSA, nil)
	otherEKU := p.issue("ec", "other EKU", false, interEC, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	})
	interClient := p.issue("ec", "inter client EKU", true, rootEC, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	leafOfClient := p.issue("ec", "leaf of client inter", false, interClient, nil)
	critical := p.issue("ec", "unknown critical", false, interEC, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
	})
	nonCritical := p.issue("ec", "unknown non-critical", false, interEC, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
	})
	interNC := p.issue("ec", "inter name constrained", true, rootEC, func(c *x509.Certificate) {
		c.PermittedDNSDomains = []string{"example.com"}
		c.PermittedDNSDomainsCritical = true
	})
	leafOfNC := p.issue("ec", "leaf of name constrained", false, interNC, func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com"}
		c.IPAddresses = nil
	})
	leafNC := p.issue("ec", "leaf name constrained", false, interEC, func(c *x509.Certificate) {
		c.PermittedDNSDomains = []string{"other.org"}
	})
	interRequire := p.issue("ec", "inter require explicit policy", true, rootEC, func(c *x509.Certificate) {
		c.Policies = []x509.OID{mustOID(2, 5, 29, 32, 0)}
		// PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] 0 }; CreateCertificate does not write it.
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 36}, Critical: true, Value: []byte{0x30, 3, 0x80, 1, 0}}}
	})
	leafOfRequire := p.issue("ec", "leaf of require explicit", false, interRequire, func(c *x509.Certificate) {
		c.Policies = []x509.OID{mustOID(1, 2, 3)}
	})

	cases := []chainCase{
		{name: "EC", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "example.com"},
		{name: "EC with root sent", roots: certs(rootEC), chain: certs(leafEC, interEC, rootEC), host: "example.com"},
		{name: "EC shuffled with extras", roots: certs(rootRSA, rootEC), chain: certs(leafEC, rootRSA, leafRSA, interRSA, interEC), host: "example.com"},
		{name: "RSA PKCS1", roots: certs(rootRSA), chain: certs(leafRSA, interRSA), host: "example.com"},
		{name: "RSA PSS", roots: certs(rootPSS), chain: certs(leafPSS, interPSS), host: "example.com"},
		{name: "mixed", roots: certs(rootRSA), chain: certs(leafMixed, interMixed), host: "example.com"},
		{name: "1024 over 4096", roots: certs(root1024), chain: certs(leaf4096), host: "example.com", stricter: true},
		{name: "RSA-1024 leaf", roots: certs(rootRSA), chain: certs(leaf1024, interRSA), host: "example.com", stricter: true},
		{name: "leaf KU without digitalSignature", roots: certs(rootEC), chain: certs(kuNoSign, interEC), host: "example.com", stricter: true},
		{name: "leaf KU with digitalSignature", roots: certs(rootEC), chain: certs(kuSign, interEC), host: "example.com"},
		{name: "leaf without KU", roots: certs(rootEC), chain: certs(noKU, interEC), host: "example.com"},
		{name: "wrong root", roots: certs(rootRSA), chain: certs(leafEC, interEC), host: "example.com", wantErr: true},
		{name: "missing intermediate", roots: certs(rootEC), chain: certs(leafEC), host: "example.com", wantErr: true},
		{name: "self-signed leaf trusted", roots: certs(selfSigned), chain: certs(selfSigned), host: "example.com"},
		{name: "self-signed leaf untrusted", roots: certs(rootEC), chain: certs(selfSigned), host: "example.com", wantErr: true},

		{name: "wildcard", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "a.wild.example.com"},
		{name: "wildcard upper case", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "A.WILD.Example.COM."},
		{name: "wildcard two labels", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "a.b.wild.example.com", wantErr: true},
		{name: "wildcard bare", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "wild.example.com", wantErr: true},
		{name: "wrong name", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "example.org", wantErr: true},
		{name: "IPv4", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "10.0.0.1"},
		{name: "IPv4 mapped", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "::ffff:10.0.0.1"},
		{name: "IPv6", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "[2001:db8:0::1]"},
		{name: "IPv6 zone", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "2001:db8::1%eth0", since: "go1.27"},
		{name: "wrong IP", roots: certs(rootEC), chain: certs(leafEC, interEC), host: "10.0.0.2", wantErr: true},
		{name: "no name check", roots: certs(rootEC), chain: certs(leafEC, interEC)},

		{name: "expired", roots: certs(rootEC), chain: certs(expired, interEC), wantErr: true},
		{name: "expired edge", roots: certs(rootEC), chain: certs(expired, interEC), at: lt.Epoch.Add(-time.Second)},
		{name: "expired edge fraction", roots: certs(rootEC), chain: certs(expired, interEC), at: lt.Epoch.Add(-time.Second + 1), wantErr: true},
		{name: "not yet valid", roots: certs(rootEC), chain: certs(notYet, interEC), wantErr: true},
		{name: "not yet valid edge", roots: certs(rootEC), chain: certs(notYet, interEC), at: lt.Epoch.Add(time.Second)},
		{name: "intermediate expired", roots: certs(rootEC), chain: certs(leafOfExpired, interExpired), wantErr: true},
		{name: "root expired", roots: certs(rootEC), chain: certs(leafEC, interEC), at: lt.Epoch.Add(200 * 24 * time.Hour), wantErr: true},

		{name: "intermediate not CA", roots: certs(rootEC), chain: certs(leafOfNotCA, interNotCA), wantErr: true},
		{name: "intermediate without basic constraints", roots: certs(rootEC), chain: certs(leafOfNoBC, interNoBC), wantErr: true},
		{name: "intermediate without certSign", roots: certs(rootEC), chain: certs(leafOfNoCertSign, interNoCertSign), wantErr: true},
		{name: "path length 0 ok", roots: certs(rootEC), chain: certs(leafOfLen0, interLen0)},
		{name: "path length 0 exceeded", roots: certs(rootEC), chain: certs(leafOfInter2, inter2, interLen0), wantErr: true},

		{name: "client only as server", roots: certs(rootEC), chain: certs(clientOnly, interEC), wantErr: true},
		{name: "client only as client", roots: certs(rootEC), chain: certs(clientOnly, interEC), usage: lx509.ExtKeyUsageClientAuth},
		{name: "server as client", roots: certs(rootEC), chain: certs(leafEC, interEC), usage: lx509.ExtKeyUsageClientAuth, wantErr: true},
		{name: "any usage requested", roots: certs(rootEC), chain: certs(clientOnly, interEC), usage: lx509.ExtKeyUsageAny},
		{name: "any EKU", roots: certs(rootEC), chain: certs(anyEKU, interEC)},
		{name: "no EKU", roots: certs(rootEC), chain: certs(noEKU, interEC), usage: lx509.ExtKeyUsageClientAuth},
		{name: "other EKU", roots: certs(rootEC), chain: certs(otherEKU, interEC), wantErr: true},
		{name: "intermediate EKU nested", roots: certs(rootEC), chain: certs(leafOfClient, interClient), wantErr: true},

		{name: "unknown critical", roots: certs(rootEC), chain: certs(critical, interEC), wantErr: true},
		{name: "unknown non-critical", roots: certs(rootEC), chain: certs(nonCritical, interEC)},
		{name: "name constrained CA", roots: certs(rootEC), chain: certs(leafOfNC, interNC), host: "example.com", unsupported: true},
		{name: "name constrained leaf", roots: certs(rootEC), chain: certs(leafNC, interEC), host: "example.com"},
		{name: "require explicit policy", roots: certs(rootEC), chain: certs(leafOfRequire, interRequire), unsupported: true},
		{name: "P-384 CA", roots: certs(root384), chain: certs(leaf384)},
		{name: "P-384 intermediate", roots: certs(rootRSA), chain: certs(leafOfInter384, inter384), host: "example.com"},
		{name: "P-384 with SHA-512", roots: certs(rootRSA), chain: certs(leafOfInter384SHA512, inter384)},
		{name: "P-384 wrong root", roots: certs(rootEC), chain: certs(leafOfInter384, inter384), wantErr: true},
		{name: "Ed25519 chain", roots: certs(rootEd), chain: certs(leafOfEd, interEd), host: "example.com"},
		{name: "Ed25519 wrong root", roots: certs(rootEC), chain: certs(leafOfEd, interEd), wantErr: true},
		{name: "P-521 CA", roots: certs(root521), chain: certs(leaf521), unsupported: true},
		{name: "P-384 leaf", roots: certs(rootEC), chain: certs(leafOf384)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.usage == 0 {
				c.usage = lx509.ExtKeyUsageServerAuth
			}
			if c.at.IsZero() {
				c.at = lt.Epoch
			}
			roots, chain := ders(c.roots), ders(c.chain)
			stdErr := stdVerify(roots, chain, c.host, stdUsage(c.usage), c.at)
			if c.since != "" && runtime.Version() < c.since {
				// This crypto/x509 predates the case: its verdict stands in for c.since's.
				stdErr = nil
				if c.wantErr {
					stdErr = errors.New("rejected by crypto/x509 of " + c.since)
				}
			}
			if (stdErr != nil) != c.wantErr {
				t.Fatalf("crypto/x509 disagrees with the case: %v", stdErr)
			}
			v := newVerifier(t, roots, c.at, lx509.VerifierConfig{})
			var err error
			if c.host == "" {
				err = v.VerifyChainAnyName(chain, c.usage)
			} else {
				err = v.VerifyChain(chain, c.usage, []byte(c.host))
			}
			if err != nil {
				alertOf(t, err)
			}
			switch {
			case c.unsupported:
				if err != lx509.ErrUnsupported {
					t.Fatalf("got %v, want ErrUnsupported", err)
				}
			case c.stricter:
				if !lx509.Stricter(err) {
					t.Fatalf("got %v, want a stricter policy's rejection", err)
				}
			case (err != nil) != (stdErr != nil):
				t.Fatalf("got %v, crypto/x509 got %v", err, stdErr)
			}
		})
	}
}

// mustOID builds an OID without x509.ParseOID, which fails under TinyGo.
func mustOID(ints ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(ints)
	if err != nil {
		panic(err)
	}
	return oid
}

// TestVerifyPeer runs the lcrypto.Verifier contract over each supported
// CertificateVerify scheme, for servers and clients.
func TestVerifyPeer(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("rsa", "root", true, nil, nil)
	inter := p.issue("p384", "inter", true, root, nil)
	both := func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	leafEC := p.issue("ec", "leaf EC", false, inter, both)
	leafRSA := p.issue("rsa", "leaf RSA", false, inter, both)
	leaf384 := p.issue("p384", "leaf P-384", false, inter, both)
	leafEd := p.issue("ed25519", "leaf Ed25519", false, inter, both)
	transcript := make([]byte, 48)
	for _, c := range []struct {
		leaf   *lt.Cert
		scheme uint16
	}{
		{leafEC, lx509.SchemeECDSAP256SHA256},
		{leaf384, lx509.SchemeECDSAP384SHA384},
		{leafEd, lx509.SchemeEd25519},
		{leafRSA, lx509.SchemeRSAPSSSHA256},
		{leafRSA, lx509.SchemeRSAPSSSHA384},
		{leafRSA, lx509.SchemeRSAPSSSHA512},
	} {
		for _, server := range []bool{true, false} {
			msg := lt.CertificateVerifyMsg(server, transcript)
			vc := lt.VerifierCase{
				Chain:        lt.Chain{c.leaf.DER, inter.DER},
				Scheme:       c.scheme,
				PeerIsServer: server,
				Msg:          msg,
				Sig:          lt.SignCertificateVerify(t, c.leaf.Key, c.scheme, msg),
			}
			if server {
				vc.Name = []byte("example.com")
			}
			lt.Verifier(t, newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{}), vc)
		}
	}
}

// TestCertificateVerifyScheme checks schemes are matched to the leaf key and
// that TLS 1.3 forbidden or unsupported schemes are rejected.
func TestCertificateVerifyScheme(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	leafEC := p.issue("ec", "leaf EC", false, root, nil)
	leafRSA := p.issue("rsa", "leaf RSA", false, root, nil)
	leaf384 := p.issue("p384", "leaf P-384", false, root, nil)
	leaf521 := p.issue("p521", "leaf P-521", false, root, nil)
	msg := lt.CertificateVerifyMsg(true, make([]byte, 32))
	v := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{})
	for _, c := range []struct {
		name       string
		leaf       *lt.Cert
		scheme     uint16 // Offered in CertificateVerify.
		signScheme uint16 // Used to sign.
		alert      uint8  // RFC 8446 alert of the error.
	}{
		{"RSA PKCS1", leafRSA, 0x0401, 0x0401, alertIllegalParameter},
		{"RSA key as ECDSA", leafRSA, lx509.SchemeECDSAP256SHA256, 0x0804, alertIllegalParameter},
		{"ECDSA key as RSA", leafEC, lx509.SchemeRSAPSSSHA256, 0x0403, alertIllegalParameter},
		{"PSS hash mismatch", leafRSA, lx509.SchemeRSAPSSSHA256, 0x0805, alertDecryptError},
		{"P-256 key as P-384", leafEC, lx509.SchemeECDSAP384SHA384, 0x0403, alertIllegalParameter},
		{"P-384 key as P-256", leaf384, lx509.SchemeECDSAP256SHA256, 0x0503, alertIllegalParameter},
		{"P-521", leaf521, 0x0603, 0x0603, alertIllegalParameter},
	} {
		sig := lt.SignCertificateVerify(t, c.leaf.Key, c.signScheme, msg)
		err := v.VerifyPeer(lt.Chain{c.leaf.DER}, c.scheme, true, []byte("example.com"), msg, sig)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if a := alertOf(t, err); a != c.alert {
			t.Errorf("%s: %v: alert %d, want %d", c.name, err, a, c.alert)
		}
	}
}
