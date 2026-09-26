package x509_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/fs"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

var (
	corpusOnce sync.Once
	corpus     [][]byte
)

// parseCorpus returns certificates exercising most of what Parse reads, and
// crypto/x509's NIST PKITS and policy test certificates if fetched.
func parseCorpus(t testing.TB) [][]byte {
	corpusOnce.Do(func() {
		ec := lt.ECKey(t, elliptic.P256())
		root := lt.NewCert(t, lt.Template("root", true), ec, nil)
		_, edKey, _ := ed25519.GenerateKey(rand.Reader)
		uri, _ := url.Parse("spiffe://example.org/service")
		edits := []func(*x509.Certificate){
			nil,
			func(c *x509.Certificate) {
				c.DNSNames = []string{"example.com", "*.example.com"}
				c.EmailAddresses = []string{"a@example.com"}
				c.IPAddresses = []net.IP{net.IPv4(1, 2, 3, 4), net.ParseIP("::1")}
				c.URIs = []*url.URL{uri}
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}
				c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3}}
			},
			func(c *x509.Certificate) {
				c.MaxPathLen, c.MaxPathLenZero = 0, true
				c.SubjectKeyId = []byte{1, 2, 3}
				c.OCSPServer = []string{"http://ocsp.example.com"}
				c.IssuingCertificateURL = []string{"http://ca.example.com"}
				c.CRLDistributionPoints = []string{"http://crl.example.com"}
				c.Policies = []x509.OID{mustOID(1, 2, 3, 4), mustOID(2, 5, 29, 32, 0)}
			},
			func(c *x509.Certificate) {
				c.IsCA, c.MaxPathLen = true, 3
				c.PermittedDNSDomains = []string{".example.com"}
				c.ExcludedIPRanges = []*net.IPNet{{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}}
				c.Subject = pkix.Name{
					Country: []string{"AR"}, Organization: []string{"Ñandú & Co"}, SerialNumber: "42",
				}
			},
			func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{
					{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}},
					{Id: asn1.ObjectIdentifier{2, 5, 29, 36}, Critical: true, Value: []byte{0x30, 3, 0x80, 1, 0}},
					{Id: asn1.ObjectIdentifier{2, 5, 29, 54}, Value: []byte{2, 1, 1}},
				}
				c.BasicConstraintsValid = false
			},
		}
		for i, edit := range edits {
			tmpl := lt.Template("cert", i%2 == 0)
			if edit != nil {
				edit(tmpl)
			}
			corpus = append(corpus, lt.NewCert(t, tmpl, ec, root).DER)
		}
		for _, key := range []any{lt.RSAKey(t, 2048, 0), lt.ECKey(t, elliptic.P384()), lt.ECKey(t, elliptic.P521()), edKey} {
			var pub any
			switch k := key.(type) {
			case *rsa.PrivateKey:
				pub = &k.PublicKey
			case *ecdsa.PrivateKey:
				pub = &k.PublicKey
			case ed25519.PrivateKey:
				pub = k.Public()
			}
			tmpl := lt.Template("key", false)
			der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, pub, root.Key)
			if err != nil {
				t.Fatal(err)
			}
			corpus = append(corpus, der)
		}
		pss := lt.Template("pss", true)
		pss.SignatureAlgorithm = x509.SHA384WithRSAPSS
		corpus = append(corpus, lt.NewCert(t, pss, lt.RSAKey(t, 2048, 0), nil).DER)

		fsys := cryptotest.VectorFS(t, "x509")
		files, _ := fs.Glob(fsys, "nist-pkits/certs/*.crt")
		for _, f := range files {
			corpus = append(corpus, fsys[f].Data)
		}
		pems, _ := fs.Glob(fsys, "*.pem")
		for _, f := range pems {
			b := fsys[f].Data
			for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
				corpus = append(corpus, blk.Bytes)
			}
		}
	})
	return corpus
}

func TestParseCorpus(t *testing.T) {
	c := parseCorpus(t)
	if len(c) < 400 {
		t.Log("crypto/x509 testdata missing; run `go run ./internal/cmd/lcryptogen fetch` for NIST PKITS")
	}
	for _, der := range c {
		if err := compareParse(der); err != "" {
			t.Errorf("%s\n%x", err, der)
		}
	}
	var cert lx509.Certificate
	if allocs := testing.AllocsPerRun(10, func() {
		for _, der := range c {
			cert.Parse(der)
		}
	}); allocs != 0 {
		t.Errorf("Parse allocated %v times per run", allocs)
	}
}

func FuzzParse(f *testing.F) {
	for _, der := range parseCorpus(f) {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if err := compareParse(der); err != "" {
			t.Error(err)
		}
	})
}

// knownParseDivergence lists crypto/x509 errors for certificates Parse accepts
// by design; see the package documentation.
var knownParseDivergence = []string{
	"cannot parse URI",
	"NameConstraints",
	"constraint",
	"invalid public key", // Point not on its curve.
	"not on curve",
	"invalid ECDSA",
}

// compareParse returns a description of how Parse and crypto/x509 disagree on der.
func compareParse(der []byte) string {
	var c lx509.Certificate
	err := c.Parse(der)
	if err == nil && !bytes.Equal(lx509.RawSubject(der), c.RawSubject) {
		return "rawSubject differs from Parse's RawSubject"
	}
	std, stdErr := x509.ParseCertificate(der)
	if stdErr != nil {
		if err == nil {
			if runtime.Version() < "go1.27" && strings.Contains(stdErr.Error(), "unsupported string type") {
				return "" // Non-string attribute values are parsed since go1.27.
			}
			for _, s := range knownParseDivergence {
				if strings.Contains(stdErr.Error(), s) {
					return ""
				}
			}
			return "accepted; crypto/x509: " + stdErr.Error()
		}
		return ""
	}
	if err != nil {
		if lx509.Stricter(err) {
			return ""
		}
		return "rejected: " + err.Error()
	}
	var diffs []string
	check := func(field string, ok bool) {
		if !ok {
			diffs = append(diffs, field)
		}
	}
	check("Raw", bytes.Equal(c.Raw, std.Raw))
	check("RawTBSCertificate", bytes.Equal(c.RawTBSCertificate, std.RawTBSCertificate))
	check("RawIssuer", bytes.Equal(c.RawIssuer, std.RawIssuer))
	check("RawSubject", bytes.Equal(c.RawSubject, std.RawSubject))
	check("RawSubjectPublicKeyInfo", bytes.Equal(c.RawSubjectPublicKeyInfo, std.RawSubjectPublicKeyInfo))
	check("Signature", bytes.Equal(c.Signature, std.Signature))
	check("NotBefore", c.NotBefore == std.NotBefore.Unix())
	check("NotAfter", c.NotAfter == std.NotAfter.Unix())
	check("Version", int(c.Version) == std.Version)
	check("SubjectKeyId", bytes.Equal(c.SubjectKeyId, std.SubjectKeyId))
	check("AuthorityKeyId", bytes.Equal(c.AuthorityKeyId, std.AuthorityKeyId))
	check("KeyUsage", int(c.KeyUsage) == int(std.KeyUsage))
	check("BasicConstraintsValid", c.BasicConstraintsValid == std.BasicConstraintsValid)
	check("IsCA", c.IsCA == std.IsCA)
	if std.BasicConstraintsValid {
		check("MaxPathLen", c.MaxPathLen == std.MaxPathLen)
	}
	check("UnhandledCriticalExtension", c.UnhandledCriticalExtension == (len(std.UnhandledCriticalExtensions) > 0))
	check("NameConstraints", !c.NameConstraints || std.PermittedDNSDomainsCritical || hasExt(std, 30))
	check("RequireExplicitPolicy", c.RequireExplicitPolicy == (std.RequireExplicitPolicy > 0 || std.RequireExplicitPolicyZero))
	check("ExtKeyUsage", c.ExtKeyUsage == ekuOf(std))
	check("SignatureAlgorithm", c.SignatureAlgorithm == sigAlgOf(std.SignatureAlgorithm))
	switch k := std.PublicKey.(type) {
	case *rsa.PublicKey:
		check("RSA key", c.PublicKeyAlgorithm == lx509.RSA && bytes.Equal(c.PublicKey, k.N.Bytes()) && c.RSAExponent == k.E)
	case *ecdsa.PublicKey:
		point, _ := k.Bytes()
		want := map[string]lx509.PublicKeyAlgorithm{"P-224": lx509.ECDSAP224, "P-256": lx509.ECDSAP256, "P-384": lx509.ECDSAP384, "P-521": lx509.ECDSAP521}
		check("ECDSA key", c.PublicKeyAlgorithm == want[k.Curve.Params().Name] && bytes.Equal(c.PublicKey, point))
	case ed25519.PublicKey:
		check("Ed25519 key", c.PublicKeyAlgorithm == lx509.Ed25519 && bytes.Equal(c.PublicKey, k))
	case nil:
		check("unknown key", c.PublicKeyAlgorithm == lx509.UnknownPublicKeyAlgorithm)
	}
	if len(diffs) > 0 {
		return "fields differ: " + strings.Join(diffs, ", ")
	}
	return ""
}

func hasExt(c *x509.Certificate, id int) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, id}) {
			return true
		}
	}
	return false
}

func ekuOf(c *x509.Certificate) lx509.ExtKeyUsage {
	var u lx509.ExtKeyUsage
	for _, e := range c.ExtKeyUsage {
		switch e {
		case x509.ExtKeyUsageAny:
			u |= lx509.ExtKeyUsageAny
		case x509.ExtKeyUsageServerAuth:
			u |= lx509.ExtKeyUsageServerAuth
		case x509.ExtKeyUsageClientAuth:
			u |= lx509.ExtKeyUsageClientAuth
		default:
			u |= lx509.ExtKeyUsageOther
		}
	}
	if len(c.UnknownExtKeyUsage) > 0 {
		u |= lx509.ExtKeyUsageOther
	}
	return u
}

func sigAlgOf(a x509.SignatureAlgorithm) lx509.SignatureAlgorithm {
	switch a {
	case x509.SHA256WithRSA:
		return lx509.SHA256WithRSA
	case x509.SHA384WithRSA:
		return lx509.SHA384WithRSA
	case x509.SHA512WithRSA:
		return lx509.SHA512WithRSA
	case x509.SHA256WithRSAPSS:
		return lx509.SHA256WithRSAPSS
	case x509.SHA384WithRSAPSS:
		return lx509.SHA384WithRSAPSS
	case x509.SHA512WithRSAPSS:
		return lx509.SHA512WithRSAPSS
	case x509.ECDSAWithSHA256:
		return lx509.ECDSAWithSHA256
	case x509.ECDSAWithSHA384:
		return lx509.ECDSAWithSHA384
	case x509.ECDSAWithSHA512:
		return lx509.ECDSAWithSHA512
	}
	return lx509.UnknownSignatureAlgorithm
}

// TestParseExtraData appends to one DER element of a certificate at a time:
// Parse rejects data after the value it reads, where crypto/x509 may ignore it.
func TestParseExtraData(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	oidOf := func(id ...int) asn1.ObjectIdentifier { return append(asn1.ObjectIdentifier{2, 5, 29}, id...) }
	ext := func(oid asn1.ObjectIdentifier, v any) pkix.Extension {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return pkix.Extension{Id: oid, Value: b}
	}
	type mapping struct{ Issuer, Subject asn1.ObjectIdentifier }
	type constraints struct {
		Require int `asn1:"optional,tag:0"`
	}
	ca := p.issue("ec", "ca", true, root, func(c *x509.Certificate) {
		c.MaxPathLen = 1
		c.DNSNames = []string{"example.com"}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.CRLDistributionPoints = []string{"http://example.com/crl"}
		c.OCSPServer = []string{"http://example.com/ocsp"}
		policy, err := x509.OIDFromInts([]uint64{2, 23, 140, 1, 2, 1})
		if err != nil {
			t.Fatal(err)
		}
		c.Policies = []x509.OID{policy}
		c.ExtraExtensions = []pkix.Extension{
			ext(oidOf(33), []mapping{{asn1.ObjectIdentifier{1, 2, 3}, asn1.ObjectIdentifier{1, 2, 4}}}),
			ext(oidOf(36), constraints{Require: 1}),
			ext(oidOf(54), 0),
		}
	}).DER
	std, err := x509.ParseCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	extPath := func(oid asn1.ObjectIdentifier, inner ...int) []int {
		for i, e := range std.Extensions {
			if e.Id.Equal(oid) {
				return append([]int{0, 7, 0, i, 1 + btoi(e.Critical)}, inner...)
			}
		}
		t.Fatalf("no extension %v", oid)
		return nil
	}
	null := []byte{0x05, 0x00}
	for _, tc := range []struct {
		name  string
		paths [][]int // Child indices from the Certificate SEQUENCE down.
		extra []byte
		want  error
	}{
		{"certificate", [][]int{{}}, null, lx509.ErrExtraData},
		{"tbsCertificate", [][]int{{0}}, null, lx509.ErrExtraData},
		{"signature algorithm", [][]int{{0, 2}, {1}}, []byte{0x05, 0x00, 0x05, 0x00}, lx509.ErrExtraData}, // One NULL is parameters.
		{"validity", [][]int{{0, 4}}, null, lx509.ErrExtraData},
		{"attribute", [][]int{{0, 5, 0, 0}}, null, lx509.ErrExtraData},
		{"empty RDN", [][]int{{0, 5}}, []byte{0x31, 0x00}, lx509.ErrEmptyRDN},
		{"subjectPublicKeyInfo", [][]int{{0, 6}}, null, lx509.ErrExtraData},
		{"public key algorithm", [][]int{{0, 6, 0}}, null, lx509.ErrExtraData},
		{"extension", [][]int{extPath(oidOf(15))[:4]}, null, lx509.ErrExtraData},
		{"key usage", [][]int{extPath(oidOf(15))}, null, lx509.ErrExtraData},
		{"basic constraints", [][]int{extPath(oidOf(19))}, null, lx509.ErrExtraData},
		{"basic constraints SEQUENCE", [][]int{extPath(oidOf(19), 0)}, null, lx509.ErrExtraData},
		{"subject alternative name", [][]int{extPath(oidOf(17))}, null, lx509.ErrExtraData},
		{"extended key usage", [][]int{extPath(oidOf(37))}, null, lx509.ErrExtraData},
		{"subject key identifier", [][]int{extPath(oidOf(14))}, null, lx509.ErrExtraData},
		{"authority key identifier", [][]int{extPath(oidOf(35))}, null, lx509.ErrExtraData},
		{"CRL distribution points", [][]int{extPath(oidOf(31))}, null, lx509.ErrExtraData},
		{"certificate policies", [][]int{extPath(oidOf(32))}, null, lx509.ErrExtraData},
		{"policy mappings", [][]int{extPath(oidOf(33))}, null, lx509.ErrExtraData},
		{"policy mapping", [][]int{extPath(oidOf(33), 0, 0)}, null, lx509.ErrExtraData},
		{"policy constraints", [][]int{extPath(oidOf(36))}, null, lx509.ErrExtraData},
		{"policy constraints SEQUENCE", [][]int{extPath(oidOf(36), 0)}, null, lx509.ErrExtraData},
		{"inhibit anyPolicy", [][]int{extPath(oidOf(54))}, null, lx509.ErrExtraData},
		{"authority information access", [][]int{extPath(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1})}, null, lx509.ErrExtraData},
	} {
		der := ca
		for _, path := range tc.paths {
			der = extendDER(t, der, path, tc.extra)
		}
		var c lx509.Certificate
		if err := c.Parse(der); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if diff := compareParse(der); diff != "" {
			t.Errorf("%s: %s", tc.name, diff)
		}
	}
	var c lx509.Certificate
	if err := c.Parse(ca); err != nil {
		t.Fatal("unmodified:", err)
	}
}

// TestParseEmpty checks RFC 5280's rules on empty names and extended key usage.
func TestParseEmpty(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	sanDNS, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.com")}})
	if err != nil {
		t.Fatal(err)
	}
	emptySubject := func(c *x509.Certificate) { c.Subject = pkix.Name{} }
	for _, tc := range []struct {
		name   string
		parent *lt.Cert
		isCA   bool
		edit   func(*x509.Certificate)
		want   error
	}{
		{"subject, critical SAN", root, false, emptySubject, nil},
		{"subject, no SAN", root, false, func(c *x509.Certificate) { emptySubject(c); c.DNSNames, c.IPAddresses = nil, nil }, lx509.ErrEmptySubject},
		{"subject, non-critical SAN", root, false, func(c *x509.Certificate) {
			emptySubject(c)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanDNS}}
		}, lx509.ErrEmptySubject},
		{"CA subject, critical SAN", root, true, func(c *x509.Certificate) { emptySubject(c); c.DNSNames = []string{"example.com"} }, lx509.ErrEmptySubject},
		{"issuer", nil, true, func(c *x509.Certificate) { emptySubject(c); c.DNSNames = []string{"example.com"} }, lx509.ErrEmptyIssuer},
		{"extended key usage", root, false, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}}}
		}, lx509.ErrEmptyEKU},
	} {
		der := p.issue("ec", tc.name, tc.isCA, tc.parent, tc.edit).DER
		var c lx509.Certificate
		if err := c.Parse(der); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if diff := compareParse(der); diff != "" {
			t.Errorf("%s: %s", tc.name, diff)
		}
	}
}

// TestParseCriticalSAN checks that a critical subject alternative name with
// no DNS name, IP address, email address or URI is unhandled, as crypto/x509
// reports it.
func TestParseCriticalSAN(t *testing.T) {
	p := &pki{t: t}
	dirName, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true,
		Bytes: []byte{0x30, 0x00}})
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: dirName})
	if err != nil {
		t.Fatal(err)
	}
	for _, critical := range []bool{false, true} {
		der := p.issue("ec", "leaf", false, nil, func(c *x509.Certificate) {
			c.DNSNames, c.IPAddresses = nil, nil
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: critical, Value: san}}
		}).DER
		var c lx509.Certificate
		if err := c.Parse(der); err != nil {
			t.Fatal(err)
		}
		if c.UnhandledCriticalExtension != critical {
			t.Errorf("critical %v: UnhandledCriticalExtension = %v", critical, c.UnhandledCriticalExtension)
		}
		if diff := compareParse(der); diff != "" {
			t.Errorf("critical %v: %s", critical, diff)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// extendDER returns der with extra appended to the contents of the element at
// path, child indices from der's outer element down.
func extendDER(t *testing.T, der []byte, path []int, extra []byte) []byte {
	t.Helper()
	var v asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) > 0 {
		t.Fatalf("path %v: %v", path, err)
	}
	if len(path) == 0 {
		v.Bytes = append(v.Bytes[:len(v.Bytes):len(v.Bytes)], extra...)
	} else {
		var out []byte
		rest := v.Bytes
		for i := 0; len(rest) > 0; i++ {
			var child asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &child); err != nil {
				t.Fatalf("path %v: %v", path, err)
			}
			b := child.FullBytes
			if i == path[0] {
				b = extendDER(t, b, path[1:], extra)
			}
			out = append(out, b...)
		}
		v.Bytes = out
	}
	v.FullBytes = nil
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
