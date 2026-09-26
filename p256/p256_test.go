package p256

import (
	"crypto/ecdh"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
)

func TestContract(t *testing.T) {
	lcryptotest.Exchanger(t, new(Exchanger), new(Exchanger), ShareSize, ShareSize, SharedSize)
}

// TestDifferential checks public keys and shared secrets against crypto/ecdh.
func TestDifferential(t *testing.T) {
	rand := lcryptotest.NewRand(5)
	var x Exchanger
	var share [ShareSize]byte
	var shared [SharedSize]byte
	for range 30 {
		if _, err := x.ClientGenerateRekey(share[:], rand); err != nil {
			t.Fatal(err)
		}
		priv, err := ecdh.P256().NewPrivateKey(x.priv[:])
		if err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "public key", share[:], priv.PublicKey().Bytes())
		peer, _ := ecdh.P256().GenerateKey(rand)
		if _, err := x.ClientShared(shared[:], peer.PublicKey().Bytes()); err != nil {
			t.Fatal(err)
		}
		want, _ := priv.ECDH(peer.PublicKey())
		lcryptotest.Equal(t, "shared", shared[:], want)
	}
	bad := share
	bad[40] ^= 1 // Off the curve.
	if _, err := x.ClientShared(shared[:], bad[:]); err == nil {
		t.Error("accepted point off the curve")
	}
}
