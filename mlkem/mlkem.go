// Package mlkem implements ML-KEM-768 of FIPS 203, TLS 1.3 group MLKEM768
// (0x0201), as an [lcrypto.Exchanger].
//
// The implementation is the Go standard library's, ported by lcryptogen.
//
// Memory: Exchanger768 holds both key halves and their scratch space, about 28 KiB;
// declare it once and reuse it. The arithmetic passes 512 byte polynomials by value,
// peaking near 6.5 KiB of stack. TinyGo keeps such values on the stack only when the
// goroutine stack is at least 16 KiB (i.e. -stack-size=16KB); with smaller stacks
// they are heap allocated.
package mlkem

import (
	"errors"
	"io"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/std/mlkem"
)

var _ lcrypto.Exchanger = (*Exchanger768)(nil)

const (
	GroupID768         = 0x0201                        // NamedGroup MLKEM768.
	ClientShareSize768 = mlkem.EncapsulationKeySize768 // Encapsulation key.
	ServerShareSize768 = mlkem.CiphertextSize768       // Ciphertext.
	SharedSize         = mlkem.SharedKeySize           // Shared secret length.
	seedSize           = mlkem.SeedSize
)

var (
	errShareSize = errors.New("mlkem: key share of wrong length")
	errNoKey     = errors.New("mlkem: ClientShared before ClientGenerateRekey")
)

// Exchanger768 is ML-KEM-768 key encapsulation. The client generates a
// decapsulation key and sends its encapsulation key; the server encapsulates a
// shared secret to it and returns the ciphertext. Its zero value is ready for use.
// Exchanger768 is not safe for concurrent use.
type Exchanger768 struct {
	dk    mlkem.DecapsulationKey768
	ek    mlkem.EncapsulationKey768
	seed  [seedSize]byte
	m     [32]byte
	keyed bool
}

// ClientGenerateRekey draws a decapsulation key from rand and writes its encapsulation key to dstClientShare.
func (x *Exchanger768) ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (int, error) {
	if len(dstClientShare) < ClientShareSize768 {
		return 0, io.ErrShortBuffer
	}
	x.Zeroize()
	_, err := io.ReadFull(rand, x.seed[:])
	if err == nil {
		err = mlkem.InitDecapsulationKey768(&x.dk, x.seed[:])
	}
	clear(x.seed[:])
	if err != nil {
		x.Zeroize()
		return 0, err
	}
	x.keyed = true
	return len(x.dk.AppendEncapsulationKey(dstClientShare[:0])), nil
}

// ServerSharedRekey encapsulates a secret drawn from rand to the encapsulation key
// clientShare, writing the ciphertext to dstServerShare and the secret to dstShared.
// Secret state is wiped on return.
func (x *Exchanger768) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	if len(dstServerShare) < ServerShareSize768 || len(dstShared) < SharedSize {
		return 0, 0, io.ErrShortBuffer
	} else if len(clientShare) != ClientShareSize768 {
		return 0, 0, errShareSize
	}
	defer x.Zeroize()
	if err := mlkem.ParseEncapsulationKey768(&x.ek, clientShare); err != nil {
		return 0, 0, err
	}
	if _, err := io.ReadFull(rand, x.m[:]); err != nil {
		return 0, 0, err
	}
	K := x.ek.EncapsulateTo((*[ServerShareSize768]byte)(dstServerShare), &x.m)
	return ServerShareSize768, copy(dstShared, K), nil
}

// ClientShared decapsulates the ciphertext serverShare and writes the shared secret
// to dstShared. A tampered ciphertext yields a pseudorandom secret, not an error,
// per FIPS 203 implicit rejection; the handshake then fails at Finished.
func (x *Exchanger768) ClientShared(dstShared, serverShare []byte) (int, error) {
	if len(dstShared) < SharedSize {
		return 0, io.ErrShortBuffer
	} else if len(serverShare) != ServerShareSize768 {
		return 0, errShareSize
	} else if !x.keyed {
		return 0, errNoKey
	}
	K, err := x.dk.Decapsulate(serverShare)
	if err != nil {
		return 0, err
	}
	return copy(dstShared, K), nil
}

// Zeroize wipes both keys, the shared secret and scratch space.
func (x *Exchanger768) Zeroize() {
	x.dk.Zeroize()
	x.ek.Zeroize()
	clear(x.seed[:])
	clear(x.m[:])
	x.keyed = false
}
