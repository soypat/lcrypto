package x509_test

import (
	"crypto/x509"
	"sync"
	"testing"
	"time"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

func TestVerifierConfigure(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	inter := p.issue("ec", "inter", true, root, nil)
	leaf := p.issue("ec", "leaf", false, inter, nil)
	good := lt.Chain{root.DER}
	clock := func() int64 { return lt.Epoch.UnixNano() }
	for _, tc := range []struct {
		name string
		cfg  lx509.VerifierConfig
	}{
		{"nil roots", lx509.VerifierConfig{Nanotime: clock}},
		{"no roots", lx509.VerifierConfig{Roots: lt.Chain{}, Nanotime: clock}},
		{"no clock", lx509.VerifierConfig{Roots: good}},
		{"unparsable root", lx509.VerifierConfig{Roots: lt.Chain{root.DER, []byte{0x30, 0}}, Nanotime: clock}},
		{"negative MaxPeerCerts", lx509.VerifierConfig{Roots: good, Nanotime: clock, MaxPeerCerts: -1}},
		{"negative MaxChainLen", lx509.VerifierConfig{Roots: good, Nanotime: clock, MaxChainLen: -1}},
		{"MaxChainLen over capacity", lx509.VerifierConfig{Roots: good, Nanotime: clock, MaxChainLen: lx509.MaxChainLen + 1}},
		{"negative MaxSignatureChecks", lx509.VerifierConfig{Roots: good, Nanotime: clock, MaxSignatureChecks: -1}},
		{"MinRSABits below rsa.MinBits", lx509.VerifierConfig{Roots: good, Nanotime: clock, MinRSABits: 512}},
		{"MinRSABits above rsa.MaxBits", lx509.VerifierConfig{Roots: good, Nanotime: clock, MinRSABits: 8192}},
	} {
		v := newVerifier(t, good, lt.Epoch, lx509.VerifierConfig{})
		if err := v.Configure(tc.cfg); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if err := v.VerifyChainAnyName(lt.Chain{leaf.DER, inter.DER}, lx509.ExtKeyUsageAny); err == nil {
			t.Errorf("%s: failed Configure kept the previous configuration", tc.name)
		}
	}
	v := newVerifier(t, good, lt.Epoch, lx509.VerifierConfig{})
	if err := v.VerifyChain(lt.Chain{leaf.DER, inter.DER}, lx509.ExtKeyUsageAny, nil); err == nil {
		t.Error("VerifyChain without a name accepted: skipping the check must be explicit")
	}
	if err := v.VerifyChain(lt.Chain{leaf.DER, inter.DER}, lx509.ExtKeyUsageAny, []byte("example.com")); err != nil {
		t.Error(err)
	}
	var zero lx509.Verifier
	if err := zero.VerifyChainAnyName(lt.Chain{leaf.DER, inter.DER}, lx509.ExtKeyUsageAny); err == nil {
		t.Error("unconfigured Verifier accepted a chain")
	}
}

// TestVerifierLimits checks each limit rejects the first chain beyond it.
// The chain leaf, inter to root is 3 long, has 2 peer certificates and needs
// 2 signature checks.
func TestVerifierLimits(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	inter := p.issue("ec", "inter", true, root, nil)
	leaf := p.issue("ec", "leaf", false, inter, nil)
	chain := lt.Chain{leaf.DER, inter.DER}
	for _, tc := range []struct {
		name    string
		cfg     lx509.VerifierConfig
		wantErr bool
	}{
		{"defaults", lx509.VerifierConfig{}, false},
		{"MaxPeerCerts 2", lx509.VerifierConfig{MaxPeerCerts: 2}, false},
		{"MaxPeerCerts 1", lx509.VerifierConfig{MaxPeerCerts: 1}, true},
		{"MaxChainLen 3", lx509.VerifierConfig{MaxChainLen: 3}, false},
		{"MaxChainLen 2", lx509.VerifierConfig{MaxChainLen: 2}, true},
		{"MaxSignatureChecks 2", lx509.VerifierConfig{MaxSignatureChecks: 2}, false},
		{"MaxSignatureChecks 1", lx509.VerifierConfig{MaxSignatureChecks: 1}, true},
	} {
		v := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, tc.cfg)
		if err := v.VerifyChainAnyName(chain, lx509.ExtKeyUsageAny); (err != nil) != tc.wantErr {
			t.Errorf("%s: got %v, want error %t", tc.name, err, tc.wantErr)
		}
	}
}

// TestConcurrentConfigure runs Configure against the other methods, for the
// race detector.
func TestConcurrentConfigure(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	leaf := p.issue("ec", "leaf", false, root, nil)
	key := marshalKey(t, leaf)
	chain, roots := lt.Chain{leaf.DER}, lt.Chain{root.DER}
	var cred lx509.Credential
	var v lx509.Verifier
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if i%2 == 0 {
					cred.Configure(lx509.CredentialConfig{Chain: chain, Key: key})
					v.Configure(lx509.VerifierConfig{Roots: roots, Nanotime: func() int64 { return lt.Epoch.UnixNano() }})
					cred.Zeroize()
					continue
				}
				var buf [1024]byte
				cred.NumCerts()
				cred.Cert(buf[:], 0)
				cred.CertView(0)
				cred.Scheme([]uint16{lx509.SchemeECDSAP256SHA256})
				v.VerifyChainAnyName(chain, lx509.ExtKeyUsageAny)
			}
		}()
	}
	wg.Wait()
}

// TestMinRSABits checks the RSA minimum applies to signing keys and the leaf.
func TestMinRSABits(t *testing.T) {
	p := &pki{t: t}
	root1024 := p.issue("rsa1024", "root RSA-1024", true, nil, nil)
	leafUnder1024 := p.issue("ec", "leaf under RSA-1024", false, root1024, nil)
	root := p.issue("rsa", "root RSA-2048", true, nil, nil)
	leaf1024 := p.issue("rsa1024", "leaf RSA-1024", false, root, nil)
	leaf2048 := p.issue("rsa", "leaf RSA-2048", false, root, nil)
	for _, tc := range []struct {
		name    string
		root    *lt.Cert
		leaf    *lt.Cert
		min     int
		wantErr bool
	}{
		{"1024 CA, default", root1024, leafUnder1024, 0, true},
		{"1024 CA, 1024", root1024, leafUnder1024, 1024, false},
		{"1024 leaf, default", root, leaf1024, 0, true},
		{"1024 leaf, 1024", root, leaf1024, 1024, false},
		{"2048 leaf, default", root, leaf2048, 0, false},
		{"2048 leaf, 3072", root, leaf2048, 3072, true},
	} {
		v := newVerifier(t, lt.Chain{tc.root.DER}, lt.Epoch, lx509.VerifierConfig{MinRSABits: tc.min})
		if err := v.VerifyChain(lt.Chain{tc.leaf.DER}, lx509.ExtKeyUsageAny, []byte("example.com")); (err != nil) != tc.wantErr {
			t.Errorf("%s: got %v, want error %t", tc.name, err, tc.wantErr)
		}
	}
}

// TestAlerts checks the alert of each kind of rejection.
func TestAlerts(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	other := p.issue("ec", "other root", true, nil, nil)
	leaf := p.issue("ec", "leaf", false, root, nil)
	expired := p.issue("ec", "expired", false, root, func(c *x509.Certificate) { c.NotAfter = lt.Epoch.Add(-time.Second) })
	v := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{})
	msg := lt.CertificateVerifyMsg(true, make([]byte, 32))
	sig := lt.SignCertificateVerify(t, leaf.Key, lx509.SchemeECDSAP256SHA256, msg)
	for _, tc := range []struct {
		name  string
		err   error
		alert uint8
	}{
		{"unknown authority", v.VerifyChain(lt.Chain{p.issue("ec", "stranger", false, other, nil).DER}, lx509.ExtKeyUsageAny, []byte("example.com")), alertUnknownCA},
		{"expired", v.VerifyChain(lt.Chain{expired.DER}, lx509.ExtKeyUsageAny, []byte("example.com")), alertCertificateExpired},
		{"wrong name", v.VerifyChain(lt.Chain{leaf.DER}, lx509.ExtKeyUsageAny, []byte("example.org")), alertBadCertificate},
		{"garbage", v.VerifyChain(lt.Chain{[]byte{0x30, 0}}, lx509.ExtKeyUsageAny, []byte("example.com")), alertBadCertificate},
		{"no certificates", v.VerifyChain(lt.Chain{}, lx509.ExtKeyUsageAny, []byte("example.com")), alertCertificateRequired},
		{"bad CertificateVerify", v.VerifyPeer(lt.Chain{leaf.DER}, lx509.SchemeECDSAP256SHA256, true, []byte("example.com"), msg[1:], sig), alertDecryptError},
		{"unconfigured", new(lx509.Verifier).VerifyChain(lt.Chain{leaf.DER}, lx509.ExtKeyUsageAny, []byte("example.com")), alertInternalError},
	} {
		if tc.err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else if a := alertOf(t, tc.err); a != tc.alert {
			t.Errorf("%s: %v: alert %d, want %d", tc.name, tc.err, a, tc.alert)
		}
	}
	if alertOf(t, lx509.ErrUnsupported) != alertUnsupportedCertificate {
		t.Error("ErrUnsupported: want unsupported_certificate")
	}
}
