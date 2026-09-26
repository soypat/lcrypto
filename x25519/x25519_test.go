package x25519

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
	rand := lcryptotest.NewRand(2)
	var x Exchanger
	var share, shared [32]byte
	for range 50 {
		if _, err := x.ClientGenerateRekey(share[:], rand); err != nil {
			t.Fatal(err)
		}
		priv, err := ecdh.X25519().NewPrivateKey(x.priv[:])
		if err != nil {
			t.Fatal(err)
		}
		lcryptotest.Equal(t, "public key", share[:], priv.PublicKey().Bytes())
		peer, _ := ecdh.X25519().GenerateKey(rand)
		if _, err := x.ClientShared(shared[:], peer.PublicKey().Bytes()); err != nil {
			t.Fatal(err)
		}
		want, _ := priv.ECDH(peer.PublicKey())
		lcryptotest.Equal(t, "shared", shared[:], want)
	}
	// RFC 7748 5: low order points must be rejected.
	x.ClientGenerateRekey(share[:], rand)
	if _, err := x.ClientShared(shared[:], make([]byte, 32)); err == nil {
		t.Error("accepted zero point")
	}
}
