package mlkem

import (
	stdmlkem "crypto/mlkem"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

func TestContract(t *testing.T) {
	lcryptotest.Exchanger(t, new(Exchanger768), new(Exchanger768), ClientShareSize768, ServerShareSize768, SharedSize)
}

// TestDifferential runs each side against crypto/mlkem as the peer.
func TestDifferential(t *testing.T) {
	rand := lcryptotest.NewRand(3)
	x := new(Exchanger768)
	cs := make([]byte, ClientShareSize768)
	ss := make([]byte, ServerShareSize768)
	shared := make([]byte, SharedSize)
	for range 10 {
		// lcrypto client, std server.
		if _, err := x.ClientGenerateRekey(cs, rand); err != nil {
			t.Fatal(err)
		}
		ek, err := stdmlkem.NewEncapsulationKey768(cs)
		if err != nil {
			t.Fatal(err)
		}
		want, ct := ek.Encapsulate()
		if _, err := x.ClientShared(shared, ct); err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "client shared", shared, want)

		// std client, lcrypto server.
		dk, _ := stdmlkem.GenerateKey768()
		if _, _, err := x.ServerSharedRekey(ss, shared, dk.EncapsulationKey().Bytes(), rand); err != nil {
			t.Fatal(err)
		}
		want, err = dk.Decapsulate(ss)
		if err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "server shared", shared, want)
	}
}
