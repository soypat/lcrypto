package x509_test

import (
	"io"
	"slices"
	"testing"

	lecdsa "github.com/soypat/lcrypto/ecdsa"
	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

// p521Verifier claims a key kind Verifier does not dispatch.
type p521Verifier struct{}

func (p521Verifier) PublicKeyAlgorithm() lx509.PublicKeyAlgorithm { return lx509.ECDSAP521 }
func (p521Verifier) VerifySignature(*lx509.Certificate, lx509.SignatureAlgorithm, []byte, []byte) error {
	return nil
}

// rsaSigner claims a key kind Credential does not sign with.
type rsaSigner struct{}

func (rsaSigner) PublicKeyAlgorithm() lx509.PublicKeyAlgorithm   { return lx509.RSA }
func (rsaSigner) SetKey([]byte) ([]byte, error)                  { return nil, nil }
func (rsaSigner) Sign(sig, msg []byte, _ io.Reader) (int, error) { return 0, nil }
func (rsaSigner) Zeroize()                                       {}

// TestP256Only checks a Verifier and Credential given only P-256 work on a
// P-256 chain and reject the other algorithms with ErrUnsupported.
func TestP256Only(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	leaf := p.issue("ec", "leaf", false, root, nil)
	v := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{
		Algorithms: []lx509.SignatureVerifier{new(lx509.P256Verifier)},
	})
	if err := v.VerifyChainAnyName(lt.Chain{leaf.DER}, lx509.ExtKeyUsageAny); err != nil {
		t.Fatal(err)
	}
	if got := v.Schemes(nil); !slices.Equal(got, []uint16{lx509.SchemeECDSAP256SHA256}) {
		t.Errorf("Schemes = %#x", got)
	}
	cred := new(lx509.Credential)
	key := marshalKey(t, leaf)
	if err := cred.Configure(lx509.CredentialConfig{Chain: lt.Chain{leaf.DER}, Key: key,
		Signers: []lx509.KeySigner{new(lx509.P256Signer)}}); err != nil {
		t.Fatal(err)
	}
	lt.Credential(t, cred, v, lx509.SchemeECDSAP256SHA256, lecdsa.P256SignatureMaxSize)

	for _, kind := range []string{"p384", "ed25519", "rsa"} {
		other := p.issue(kind, "root "+kind, true, nil, nil)
		otherLeaf := p.issue("ec", "leaf under "+kind, false, other, nil)
		v := newVerifier(t, lt.Chain{other.DER}, lt.Epoch, lx509.VerifierConfig{
			Algorithms: []lx509.SignatureVerifier{new(lx509.P256Verifier)},
		})
		if err := v.VerifyChainAnyName(lt.Chain{otherLeaf.DER}, lx509.ExtKeyUsageAny); err != lx509.ErrUnsupported {
			t.Errorf("%s root: got %v, want ErrUnsupported", kind, err)
		}
	}
	// A P-384 leaf under the P-256 root: the chain verifies, its
	// CertificateVerify does not.
	p384Leaf := p.issue("p384", "leaf p384", false, root, nil)
	err := v.VerifyPeer(lt.Chain{p384Leaf.DER}, lx509.SchemeECDSAP384SHA384, true, []byte("example.com"),
		lt.CertificateVerifyMsg(false, []byte("transcript")), make([]byte, 64))
	if err != lx509.ErrUnsupported {
		t.Errorf("P-384 CertificateVerify: got %v, want ErrUnsupported", err)
	}
	cred2 := new(lx509.Credential)
	if err := cred2.Configure(lx509.CredentialConfig{Chain: lt.Chain{p384Leaf.DER}, Key: marshalKey(t, p384Leaf),
		Signers: []lx509.KeySigner{new(lx509.P256Signer)}}); err == nil {
		t.Error("Credential accepted a P-384 key without a P-384 signer")
	}
}

func TestSchemes(t *testing.T) {
	p := &pki{t: t}
	root := p.issue("ec", "root", true, nil, nil)
	v := newVerifier(t, lt.Chain{root.DER}, lt.Epoch, lx509.VerifierConfig{})
	want := []uint16{lx509.SchemeECDSAP256SHA256, lx509.SchemeEd25519, lx509.SchemeECDSAP384SHA384,
		lx509.SchemeRSAPSSSHA256, lx509.SchemeRSAPSSSHA384, lx509.SchemeRSAPSSSHA512}
	if got := v.Schemes(nil); !slices.Equal(got, want) {
		t.Errorf("Schemes = %#x, want %#x", got, want)
	}
	var zero lx509.Verifier
	if got := zero.Schemes(nil); len(got) != 0 {
		t.Errorf("unconfigured Schemes = %#x", got)
	}
}

func TestCredentialSigners(t *testing.T) {
	p := &pki{t: t}
	leaf := p.issue("ec", "leaf", false, p.issue("ec", "root", true, nil, nil), nil)
	key := marshalKey(t, leaf)
	for _, tc := range []struct {
		name    string
		signers []lx509.KeySigner
	}{
		{"none", nil},
		{"nil", []lx509.KeySigner{nil}},
		{"duplicate", []lx509.KeySigner{new(lx509.P256Signer), new(lx509.P256Signer)}},
		{"unsupported", []lx509.KeySigner{new(lx509.P256Signer), rsaSigner{}}},
		{"other key", []lx509.KeySigner{new(lx509.P384Signer), new(lx509.Ed25519Signer)}},
	} {
		var cred lx509.Credential
		if err := cred.Configure(lx509.CredentialConfig{Chain: lt.Chain{leaf.DER}, Key: key, Signers: tc.signers}); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if cred.NumCerts() != 0 {
			t.Errorf("%s: failed Configure left a chain", tc.name)
		}
	}
}
