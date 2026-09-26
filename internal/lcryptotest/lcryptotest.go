// Package lcryptotest holds helpers shared by lcrypto implementation tests.
package lcryptotest

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"unsafe"

	"github.com/soypat/lcrypto"
)

// Bytes returns the memory of *v, padding included.
func Bytes[T any](v *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))
}

// IsZero reports whether every byte of *v is zero.
func IsZero[T any](v *T) bool {
	for _, b := range Bytes(v) {
		if b != 0 {
			return false
		}
	}
	return true
}

// AEAD checks the lcrypto.AEADCipher contract common to all implementations:
// unkeyed behaviour, in-place round trip, tamper rejection, zero allocations and
// that Zeroize wipes every byte of the cipher. c must be unkeyed.
func AEAD[T any, P interface {
	*T
	lcrypto.AEADCipher
}](t *testing.T, c P, key []byte) {
	t.Helper()
	nonce := make([]byte, c.NonceSize())
	if _, err := c.Open(nil, nonce, make([]byte, c.Overhead()), nil); err == nil {
		t.Fatal("Open on unkeyed cipher succeeded")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Seal on unkeyed cipher did not panic")
			}
		}()
		c.Seal(nil, nonce, nil, nil)
	}()
	if err := c.Rekey(key[:len(key)-1]); err == nil {
		t.Fatal("Rekey accepted short key")
	}
	if !IsZero((*T)(c)) {
		t.Fatal("failed Rekey left state behind")
	}
	if err := c.Rekey(key); err != nil {
		t.Fatal(err)
	}

	const msgLen = 100
	buf := make([]byte, msgLen, msgLen+c.Overhead())
	for i := range buf {
		buf[i] = byte(i)
	}
	ad := []byte("header")
	sealed := c.Seal(buf[:0], nonce, buf, ad)
	opened, err := c.Open(sealed[:0], nonce, sealed, ad)
	if err != nil {
		t.Fatal(err)
	}
	for i := range opened {
		if opened[i] != byte(i) {
			t.Fatal("round trip mismatch")
		}
	}
	sealed = c.Seal(buf[:0], nonce, buf[:msgLen], ad)
	sealed[3] ^= 1
	if _, err := c.Open(nil, nonce, sealed, ad); err == nil {
		t.Fatal("Open accepted tampered ciphertext")
	}

	allocs := testing.AllocsPerRun(50, func() {
		if err := c.Rekey(key); err != nil {
			t.Fatal(err)
		}
		sealed := c.Seal(buf[:0], nonce, buf[:msgLen], ad)
		if _, err := c.Open(sealed[:0], nonce, sealed, ad); err != nil {
			t.Fatal(err)
		}
		c.Zeroize()
	})
	if allocs != 0 {
		t.Errorf("Rekey/Seal/Open/Zeroize allocated %v times per run", allocs)
	}

	if err := c.Rekey(key); err != nil {
		t.Fatal(err)
	}
	c.Seal(buf[:0], nonce, buf[:msgLen], ad) // Leave per-record state behind.
	c.Zeroize()
	if !IsZero((*T)(c)) {
		t.Error("Zeroize left non-zero bytes")
	}
}

// Equal fails t if got != want.
func Equal(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", what, got, want)
	}
}

// Exchanger checks the lcrypto.Exchanger contract: client and server agree on the
// shared secret, short buffers are rejected, the full exchange does not allocate
// and Zeroize wipes every byte. client and server must be distinct zero values.
func Exchanger[T any, P interface {
	*T
	lcrypto.Exchanger
}](t *testing.T, client, server P, clientShareSize, serverShareSize, sharedSize int) {
	t.Helper()
	rand := NewRand(1)
	cs := make([]byte, clientShareSize)
	ss := make([]byte, serverShareSize)
	sharedC, sharedS := make([]byte, sharedSize), make([]byte, sharedSize)

	if _, err := client.ClientShared(sharedC, ss); err == nil {
		t.Fatal("ClientShared before ClientGenerateRekey succeeded")
	}
	if _, err := client.ClientGenerateRekey(cs[:clientShareSize-1], rand); err == nil {
		t.Fatal("ClientGenerateRekey accepted short buffer")
	}
	exchange := func() {
		n, err := client.ClientGenerateRekey(cs, rand)
		if err != nil || n != clientShareSize {
			t.Fatal("ClientGenerateRekey", n, err)
		}
		nShare, nShared, err := server.ServerSharedRekey(ss, sharedS, cs, rand)
		if err != nil || nShare != serverShareSize || nShared != sharedSize {
			t.Fatal("ServerSharedRekey", nShare, nShared, err)
		}
		n, err = client.ClientShared(sharedC, ss)
		if err != nil || n != sharedSize {
			t.Fatal("ClientShared", n, err)
		}
	}
	exchange()
	Equal(t, "shared secret", sharedC, sharedS)
	if _, _, err := server.ServerSharedRekey(ss, sharedS, cs[:clientShareSize-1], rand); err == nil {
		t.Fatal("ServerSharedRekey accepted truncated client share")
	}
	if _, err := client.ClientShared(sharedC, ss[:serverShareSize-1]); err == nil {
		t.Fatal("ClientShared accepted truncated server share")
	}
	if allocs := testing.AllocsPerRun(3, exchange); allocs != 0 {
		t.Errorf("exchange allocated %v times per run", allocs)
	}
	client.Zeroize()
	server.Zeroize()
	if !IsZero((*T)(client)) || !IsZero((*T)(server)) {
		t.Error("Zeroize left non-zero bytes")
	}
}

// NewRand returns a deterministic io.Reader for tests.
func NewRand(seed byte) *rand.ChaCha8 { return rand.NewChaCha8([32]byte{seed}) }
