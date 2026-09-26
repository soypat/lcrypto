package ed25519

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest/cryptotest"
)

// TestEd25519Vectors is crypto/ed25519's: the edge cases of
// filippo.io/mostly-harmless/ed25519vectors, where implementations disagree,
// must be decided as the standard library decides them.
func TestEd25519Vectors(t *testing.T) {
	dir := cryptotest.FetchModule(t, "filippo.io/mostly-harmless/ed25519vectors", "v0.0.0-20210322192420-30a2d7243a94")
	jsonVectors, err := os.ReadFile(filepath.Join(dir, "ed25519vectors.json"))
	if err != nil {
		t.Fatalf("failed to read ed25519vectors.json: %v", err)
	}
	var vectors []struct {
		A, R, S, M string
		Flags      []string
	}
	if err := json.Unmarshal(jsonVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	var v Verifier
	for i, vec := range vectors {
		expectedToVerify := true
		for _, f := range vec.Flags {
			switch f {
			// The cofactorless verification equation rejects low order
			// residues, as RFC 8032 allows.
			case "LowOrderResidue":
				expectedToVerify = false
			// R is recomputed and compared bytewise against the canonical encoding.
			case "NonCanonicalR":
				expectedToVerify = false
			}
		}
		pub := decodeHex(t, vec.A)
		sig := append(decodeHex(t, vec.R), decodeHex(t, vec.S)...)
		didVerify := v.Verify(pub, []byte(vec.M), sig) == nil
		if didVerify && !expectedToVerify {
			t.Errorf("#%d: vector with flags %s unexpectedly verified", i, vec.Flags)
		}
		if !didVerify && expectedToVerify {
			t.Errorf("#%d: vector with flags %s unexpectedly rejected", i, vec.Flags)
		}
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Errorf("invalid hex: %v", err)
	}
	return b
}
