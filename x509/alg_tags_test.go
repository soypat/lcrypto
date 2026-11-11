//go:build lcrypto_nop384 && lcrypto_noed25519 && lcrypto_norsa

package x509_test

import (
	"crypto/x509"
	"testing"

	lecdsa "github.com/soypat/lcrypto/ecdsa"
	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

func TestP256Only(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	leaf := p.issue("ec", "leaf", false, root, nil)
	verifier := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{})
	key, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	if err != nil {
		t.Fatal(err)
	}
	cred := &lx509.Credential{}
	if err := cred.Configure(lx509.CredentialConfig{Chain: lt.Chain{leaf.DER}, Key: key}); err != nil {
		t.Fatal(err)
	}
	lt.Credential(t, cred, verifier, lx509.SchemeECDSAP256SHA256, lecdsa.P256SignatureMaxSize)

	for _, kind := range []string{"p384", "ed25519", "rsa"} {
		other := p.issue(kind, "root "+kind, true, nil, nil)
		leaf := p.issue("ec", "leaf "+kind, false, other, nil)
		v := newVerifier(t, lt.Chain{other.DER}, lt.Epoch, lx509.VerifierConfig{})
		if err := v.VerifyChainAnyName(lt.Chain{leaf.DER}, lx509.ExtKeyUsageServerAuth); err != lx509.ErrUnsupported {
			t.Errorf("%s root: got %v, want %v", kind, err, lx509.ErrUnsupported)
		}
	}
}
