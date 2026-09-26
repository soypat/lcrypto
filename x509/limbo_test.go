package x509_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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
// agree, except that Verifier may fail closed with ErrUnsupported. Where
// crypto/x509 departs from the corpus' verdicts, its own test keeps the
// justification, and neither checks CRLs, a maximum chain depth or email
// names: those cases compare the rest of verification.
//
// The Verifier accepts the longest peer chain of the corpus: MaxPeerCerts
// bounds work, not memory, so its default limit is a policy the corpus does
// not test.
func TestX509Limbo(t *testing.T) {
	var limbo x509limbo.Limbo
	if err := json.Unmarshal(cryptotest.Vectors(t, "x509limbo", "limbo.json"), &limbo); err != nil {
		t.Fatalf("failed to unmarshal limbo.json: %v", err)
	}
	maxPeer := 0
	for _, tc := range limbo.Testcases {
		maxPeer = max(maxPeer, 1+len(tc.UntrustedIntermediates))
	}
	var agree, unsupported int
	for _, tc := range limbo.Testcases {
		t.Run(tc.Id, func(t *testing.T) {
			switch runLimbo(t, tc, maxPeer) {
			case limboAgree:
				agree++
			case limboUnsupported:
				unsupported++
			}
		})
	}
	t.Logf("%d cases, longest peer chain %d: %d agree with crypto/x509, %d unsupported",
		len(limbo.Testcases), maxPeer, agree, unsupported)
}

type limboResult int

const (
	limboFailed limboResult = iota
	limboAgree
	limboUnsupported
)

func runLimbo(t *testing.T, tc x509limbo.Testcase, maxPeer int) limboResult {
	usage, stdUsage := lx509.ExtKeyUsageAny, x509.ExtKeyUsageAny
	switch {
	case len(tc.ExtendedKeyUsage) == 0:
	case slices.Equal(tc.ExtendedKeyUsage, []x509limbo.KnownEKUs{x509limbo.KnownEKUsServerAuth}):
		usage, stdUsage = lx509.ExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth
	case slices.Equal(tc.ExtendedKeyUsage, []x509limbo.KnownEKUs{x509limbo.KnownEKUsClientAuth}):
		usage, stdUsage = lx509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth
	default:
		t.Fatalf("Verifier checks one of the TLS usages, not %v: extend the test", tc.ExtendedKeyUsage)
	}
	var names []string // DNS names and IP addresses: Verifier does not match email addresses.
	if tc.ValidationKind == x509limbo.ValidationKindSERVER && tc.ExpectedPeerName != nil {
		names = append(names, tc.ExpectedPeerName.Value)
	} else if tc.ValidationKind == x509limbo.ValidationKindCLIENT {
		for _, n := range tc.ExpectedPeerNames {
			if n.Kind != x509limbo.PeerKindRFC822 {
				names = append(names, n.Value)
			}
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
	// Like crypto/x509's CertPool, trust the roots that parse: Configure
	// rejects the others.
	var parsed lt.Chain
	for _, der := range roots {
		var c lx509.Certificate
		if c.Parse(der) == nil {
			parsed = append(parsed, der)
		}
	}
	if len(parsed) == 0 {
		if stdErr == nil {
			t.Errorf("no root parses; crypto/x509 accepts (limbo expects %s)", tc.ExpectedResult)
			return limboFailed
		}
		return limboAgree
	}
	v := newVerifier(t, parsed, at, lx509.VerifierConfig{MaxPeerCerts: maxPeer})
	var err error
	if len(names) == 0 {
		err = v.VerifyChainAnyName(chain, usage)
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
		return limboUnsupported
	case err != nil && stdErr == nil:
		t.Errorf("%v; crypto/x509 accepts (limbo expects %s)", err, tc.ExpectedResult)
	default:
		return limboAgree
	}
	return limboFailed
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
