package x509_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	lt "github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
	"github.com/soypat/lcrypto/internal/lcryptotest/x509limbo"
	lx509 "github.com/soypat/lcrypto/x509"
)

// TestX509Limbo runs the x509-limbo corpus (https://x509-limbo.com) through
// Verifier and crypto/x509, as crypto/x509's TestX509Limbo does. They must
// agree, except that Verifier may fail closed with ErrUnsupported or refuse
// more than MaxPeerCerts certificates. Where crypto/x509 departs from the
// corpus' verdicts, its own test keeps the justification.
func TestX509Limbo(t *testing.T) {
	dir := cryptotest.FetchModule(t, x509limbo.X509LimboModule, x509limbo.X509LimboVersion)
	b, err := os.ReadFile(filepath.Join(dir, "limbo.json"))
	if err != nil {
		t.Fatalf("error reading limbo.json: %v", err)
	}
	var limbo x509limbo.Limbo
	if err := json.Unmarshal(b, &limbo); err != nil {
		t.Fatalf("failed to unmarshal limbo.json: %v", err)
	}
	var agree, unsupported, tooLong, skipped int
	for _, tc := range limbo.Testcases {
		t.Run(tc.Id, func(t *testing.T) {
			res, skip := runLimbo(t, tc)
			switch res {
			case limboAgree:
				agree++
			case limboUnsupported:
				unsupported++
			case limboTooLong:
				tooLong++
			case limboSkipped:
				skipped++
				t.Skip(skip)
			}
		})
	}
	t.Logf("%d cases: %d agree with crypto/x509, %d unsupported, %d over MaxPeerCerts, %d skipped",
		len(limbo.Testcases), agree, unsupported, tooLong, skipped)
}

type limboResult int

const (
	limboFailed limboResult = iota
	limboAgree
	limboUnsupported
	limboTooLong
	limboSkipped
)

// runLimbo runs tc, returning why it is skipped for limboSkipped.
func runLimbo(t *testing.T, tc x509limbo.Testcase) (limboResult, string) {
	if slices.Contains(tc.Features, x509limbo.FeatureHasCrl) || slices.Contains(tc.Features, x509limbo.FeatureMaxChainDepth) {
		return limboSkipped, "neither Verifier nor crypto/x509 checks CRLs or takes a maximum depth"
	}
	usage, stdUsage := lx509.ExtKeyUsageAny, x509.ExtKeyUsageAny
	switch {
	case len(tc.ExtendedKeyUsage) == 0:
	case slices.Equal(tc.ExtendedKeyUsage, []x509limbo.KnownEKUs{x509limbo.KnownEKUsServerAuth}):
		usage, stdUsage = lx509.ExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth
	case slices.Equal(tc.ExtendedKeyUsage, []x509limbo.KnownEKUs{x509limbo.KnownEKUsClientAuth}):
		usage, stdUsage = lx509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth
	default:
		return limboSkipped, fmt.Sprintf("Verifier checks one of the TLS usages, not %v", tc.ExtendedKeyUsage)
	}
	var names []string
	if tc.ValidationKind == x509limbo.ValidationKindSERVER && tc.ExpectedPeerName != nil {
		names = append(names, tc.ExpectedPeerName.Value)
	} else if tc.ValidationKind == x509limbo.ValidationKindCLIENT {
		for _, n := range tc.ExpectedPeerNames {
			names = append(names, n.Value)
		}
	}
	for _, n := range tc.ExpectedPeerNames {
		if n.Kind == x509limbo.PeerKindRFC822 {
			return limboSkipped, "Verifier does not match email addresses"
		}
	}
	at := time.Now()
	if tc.ValidationTime != nil {
		s, ok := tc.ValidationTime.(string)
		if !ok {
			t.Fatalf("validation time is not a string: %T %v", tc.ValidationTime, tc.ValidationTime)
		}
		if at, _ = time.Parse(time.RFC3339, s); at.IsZero() {
			t.Fatalf("invalid validation time %q", s)
		}
	}
	roots, intermediates := limboDER(t, tc.TrustedCerts), limboDER(t, tc.UntrustedIntermediates)
	peer := limboDER(t, []string{tc.PeerCertificate})
	chain := append(peer, intermediates...)

	stdErr := limboStd(roots, chain, names, stdUsage, at)
	v := &lx509.Verifier{Roots: roots, Time: func() time.Time { return at }}
	var err error
	if len(names) == 0 {
		err = v.VerifyChain(chain, usage, nil)
	}
	for _, name := range names {
		if err = v.VerifyChain(chain, usage, []byte(name)); err != nil {
			break
		}
	}
	switch {
	case err == nil && stdErr != nil:
		t.Errorf("accepted; crypto/x509: %v (limbo expects %s)", stdErr, tc.ExpectedResult)
	case err != nil && stdErr == nil && errors.Is(err, lx509.ErrUnsupported):
		t.Log("unsupported:", err)
		return limboUnsupported, ""
	case err != nil && stdErr == nil && len(chain) > lx509.MaxPeerCerts:
		t.Log("over MaxPeerCerts:", err)
		return limboTooLong, ""
	case err != nil && stdErr == nil:
		t.Errorf("%v; crypto/x509 accepts (limbo expects %s)", err, tc.ExpectedResult)
	default:
		return limboAgree, ""
	}
	return limboFailed, ""
}

// limboStd verifies as crypto/x509's TestX509Limbo does: unparsable roots and
// intermediates are ignored, and each name checked against the leaf.
func limboStd(roots, chain lt.Chain, names []string, usage x509.ExtKeyUsage, at time.Time) error {
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}
	for _, der := range roots {
		if c, err := x509.ParseCertificate(der); err == nil {
			opts.Roots.AddCert(c)
		}
	}
	for _, der := range chain[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			opts.Intermediates.AddCert(c)
		}
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	for _, name := range names {
		if err := leaf.VerifyHostname(name); err != nil {
			return err
		}
	}
	return nil
}

func limboDER(t *testing.T, pems []string) lt.Chain {
	var ders lt.Chain
	for _, p := range pems {
		block, rest := pem.Decode([]byte(p))
		if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 {
			t.Fatalf("bad certificate PEM:\n%s", p)
		}
		ders = append(ders, block.Bytes)
	}
	return ders
}
