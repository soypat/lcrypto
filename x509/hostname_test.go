package x509_test

import (
	"crypto/elliptic"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

var ipCases = []string{
	"1.2.3.4", "0.0.0.0", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "1..2.3", ".1.2.3", "1.2.3.",
	"::", "::1", "1::", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::",
	"::1:2:3:4:5:6:7", "::ffff:1.2.3.4", "::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "12345::", "1:::2",
	"1::2::3", ":1::", "1:", "fe80::1%eth0", "fe80::1%", "%eth0", "1.2.3.4%eth0", "", "a", "[::1]", "0:0:0:0:0:0:0:0",
}

func FuzzParseIP(f *testing.F) {
	for _, s := range ipCases {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ip, ok := lx509.ParseIP([]byte(s))
		want, err := netip.ParseAddr(s)
		if ok != (err == nil) || ok && ip != want.As16() {
			t.Errorf("%q: got %v %x, netip %v %v", s, ok, ip, want, err)
		}
	})
}

var hostnameSANs = []string{
	"example.com", "*.wild.example.com", "UPPER.Example.COM", "*.*.double.com", "a*.partial.com", "trailing.dot.",
	"_under.score.org", "-lead.dash.net", "*", "..", ".", "x..y", "sp ace.com", "exact-*.star.com",
}

var hostnameCases = []string{
	"example.com", "EXAMPLE.com.", "a.wild.example.com", "wild.example.com", "a.b.wild.example.com", "upper.example.com",
	"x.y.double.com", "ab.partial.com", "trailing.dot", "trailing.dot.", "_under.score.org", "-lead.dash.net", "*", ".",
	"..", "", "x..y", "sp ace.com", "ünïcode.com", "exact-*.star.com", "10.0.0.1", "[10.0.0.1]", "::ffff:10.0.0.1",
	"2001:db8::1", "[2001:db8::1]", "2001:db8::2", "[example.com]", "example.com..",
}

func FuzzVerifyHostname(f *testing.F) {
	root := lt.NewCert(f, lt.Template("root", true), lt.ECKey(f, elliptic.P256()), nil)
	tmpl := lt.Template("leaf", false)
	tmpl.DNSNames = hostnameSANs
	tmpl.IPAddresses = []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1")}
	leaf := lt.NewCert(f, tmpl, lt.ECKey(f, elliptic.P256()), root)
	var c lx509.Certificate
	if err := c.Parse(leaf.DER); err != nil {
		f.Fatal(err)
	}
	for _, h := range hostnameCases {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if runtime.Version() < "go1.27" && strings.Contains(h, "%") {
			t.Skip("IPv6 zones are accepted since go1.27")
		}
		err := c.VerifyHostname([]byte(h))
		stdErr := leaf.Cert.VerifyHostname(h)
		if (err == nil) != (stdErr == nil) {
			t.Errorf("%q: got %v, crypto/x509 %v", h, err, stdErr)
		}
	})
}
