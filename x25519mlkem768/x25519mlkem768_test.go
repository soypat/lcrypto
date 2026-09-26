package x25519mlkem768

import (
	"crypto/ecdh"
	stdmlkem "crypto/mlkem"
	"testing"

	"github.com/soypat/lcrypto/internal/lcryptotest"
	"github.com/soypat/lcrypto/mlkem"
)

func TestContract(t *testing.T) {
	lcryptotest.Exchanger(t, new(Exchanger), new(Exchanger), ClientShareSize, ServerShareSize, SharedSize)
}

// TestDifferential plays a std-built server against the lcrypto client, checking
// the draft-ietf-tls-ecdhe-mlkem share and secret layout.
func TestDifferential(t *testing.T) {
	rand := lcryptotest.NewRand(4)
	x := new(Exchanger)
	cs := make([]byte, ClientShareSize)
	shared := make([]byte, SharedSize)
	if _, err := x.ClientGenerateRekey(cs, rand); err != nil {
		t.Fatal(err)
	}
	ek, err := stdmlkem.NewEncapsulationKey768(cs[:mlkem.ClientShareSize768])
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := ecdh.X25519().NewPublicKey(cs[mlkem.ClientShareSize768:])
	if err != nil {
		t.Fatal(err)
	}
	kemShared, ct := ek.Encapsulate()
	serverPriv, _ := ecdh.X25519().GenerateKey(rand)
	dhShared, _ := serverPriv.ECDH(clientPub)
	ss := append(ct, serverPriv.PublicKey().Bytes()...)
	if _, err := x.ClientShared(shared, ss); err != nil {
		t.Fatal(err)
	}
	lcryptotest.Equal(t, "shared", shared, append(kemShared, dhShared...))
}
