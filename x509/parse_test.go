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
		if strings.Contains(err.Error(), "BIT STRING not byte aligned") || strings.Contains(err.Error(), "too many extensions") {
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
