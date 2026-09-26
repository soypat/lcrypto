package x509_test

import (
	"sync"
	"testing"

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
