package mlkem

import (
	"bytes"
	"encoding/hex"
	"flag"
	"testing"

	"github.com/soypat/lcrypto/internal/std/sha3"
)

var millionFlag = flag.Bool("million", false, "run the million vector test")

// TestAccumulated is crypto/mlkem's TestAccumulated through the Exchanger: 10k
// (100 in -short mode, 1M with -million) exchanges with keys, messages and
// ciphertexts drawn from SHAKE128 and outputs accumulated into another, whose
// hash matches the standard library's. The Exchanger reads the seed and message
// from rand in the order the upstream test draws them.
func TestAccumulated(t *testing.T) {
	n := 10000
	expected := "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
	if testing.Short() {
		n = 100
		expected = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
	}
	if *millionFlag {
		n = 1000000
		expected = "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0"
	}

	s := sha3.NewShake128()
	o := sha3.NewShake128()
	var client, server Exchanger768
	var ek [ClientShareSize768]byte
	var ct, ct1 [ServerShareSize768]byte
	var k, kk, k1 [SharedSize]byte

	for range n {
		if _, err := client.ClientGenerateRekey(ek[:], s); err != nil {
			t.Fatal(err)
		}
		o.Write(ek[:])

		if _, _, err := server.ServerSharedRekey(ct[:], k[:], ek[:], s); err != nil {
			t.Fatal(err)
		}
		o.Write(ct[:])
		o.Write(k[:])

		if _, err := client.ClientShared(kk[:], ct[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kk[:], k[:]) {
			t.Errorf("k: got %x, expected %x", kk, k)
		}

		s.Read(ct1[:])
		if _, err := client.ClientShared(k1[:], ct1[:]); err != nil {
			t.Fatal(err)
		}
		o.Write(k1[:])
	}

	got := hex.EncodeToString(o.Sum(nil))
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}
