package x509_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

// TestNISTPKITS builds and verifies every NIST PKITS certificate path with
// both Verifier and crypto/x509. They must agree, except that Verifier may
// fail closed with ErrUnsupported. Like crypto/x509, Verifier ignores CRLs,
// so the suite's own verdicts do not apply.
func TestNISTPKITS(t *testing.T) {
	fsys := cryptotest.VectorFS(t, "x509")
	var vectors []struct {
		Name     string
		CertPath []string // Trust anchor first.
	}
	if err := json.Unmarshal(fsys["nist-pkits/vectors.json"].Data, &vectors); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	var accepted, unsupported int
	for _, vec := range vectors {
		n := len(vec.CertPath)
		roots := make(lt.Chain, 1)
		chain := make(lt.Chain, n-1) // Leaf first.
		for i, name := range vec.CertPath {
			f, ok := fsys["nist-pkits/certs/"+name]
			if !ok {
				t.Fatalf("%s: missing", name)
			}
			der := f.Data
			if i == 0 {
				roots[0] = der
			} else {
				chain[n-1-i] = der
			}
		}
		stdErr := stdVerify(roots, chain, "", x509.ExtKeyUsageAny, at)
		v := newVerifier(t, roots, at, lx509.VerifierConfig{})
		err := v.VerifyChainAnyName(chain, lx509.ExtKeyUsageAny)
		switch {
		case err == nil && stdErr != nil:
			t.Errorf("%s: accepted; crypto/x509: %v", vec.Name, stdErr)
		case err != nil && stdErr == nil && errors.Is(err, lx509.ErrUnsupported):
			unsupported++
			t.Log("unsupported:", vec.Name)
		case err != nil && stdErr == nil:
			t.Errorf("%s: %v; crypto/x509 accepts", vec.Name, err)
		case err == nil:
			accepted++
		}
	}
	t.Logf("%d paths: %d accepted by both, %d accepted by crypto/x509 only (unsupported)", len(vectors), accepted, unsupported)
}
