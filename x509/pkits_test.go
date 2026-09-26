package x509_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	lx509 "github.com/soypat/lcrypto/x509"
)

// TestNISTPKITS builds and verifies every NIST PKITS certificate path with
// both Verifier and crypto/x509. They must agree, except that Verifier may
// fail closed with ErrUnsupported. Like crypto/x509, Verifier ignores CRLs,
// so the suite's own verdicts do not apply.
func TestNISTPKITS(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(stdTestdata, "nist-pkits/vectors.json"))
	if err != nil {
		t.Skip("crypto/x509 testdata missing; run `go run ./internal/cmd/lcryptogen fetch`")
	}
	var vectors []struct {
		Name     string
		CertPath []string // Trust anchor first.
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	var accepted, unsupported int
	for _, vec := range vectors {
		n := len(vec.CertPath)
		roots := make(lt.Chain, 1)
		chain := make(lt.Chain, n-1) // Leaf first.
		for i, name := range vec.CertPath {
			der, err := os.ReadFile(filepath.Join(stdTestdata, "nist-pkits/certs", name))
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				roots[0] = der
			} else {
				chain[n-1-i] = der
			}
		}
		stdErr := stdVerify(roots, chain, "", x509.ExtKeyUsageAny, at)
		v := &lx509.Verifier{Roots: roots, Time: func() time.Time { return at }}
		err := v.VerifyChain(chain, lx509.ExtKeyUsageAny, nil)
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
