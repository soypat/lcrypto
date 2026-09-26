// Package x25519 implements the X25519 key exchange of RFC 7748, TLS 1.3 group
// x25519 (0x001D), as an [lcrypto.Exchanger].
//
// The implementation is crypto/ecdh's, ported by lcryptogen.
package x25519

import (
	"errors"
	"io"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/std/x25519"
)

var _ lcrypto.Exchanger = (*Exchanger)(nil)

const (
	GroupID    = 0x001D // RFC 8446 4.2.7 NamedGroup x25519.
	ShareSize  = 32     // Public key share length of client and server.
	SharedSize = 32     // Shared secret length.
)

var (
	errShareSize = errors.New("x25519: key share must be 32 bytes")
	errLowOrder  = errors.New("x25519: low order peer share")
	errNoKey     = errors.New("x25519: ClientShared before ClientGenerateRekey")
)

// Exchanger is X25519 ephemeral Diffie-Hellman. Its zero value is ready for use.
// Exchanger is not safe for concurrent use.
type Exchanger struct {
	priv  [32]byte
	keyed bool
}

// ClientGenerateRekey draws a private key from rand and writes the public key to dstClientShare.
func (x *Exchanger) ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (int, error) {
	if len(dstClientShare) < ShareSize {
		return 0, io.ErrShortBuffer
	}
	if err := x.generate(rand); err != nil {
		return 0, err
	}
	x25519.ScalarBaseMult((*[32]byte)(dstClientShare), &x.priv)
	return ShareSize, nil
}

// ServerSharedRekey draws a private key from rand, writes its public key to dstServerShare
// and the secret shared with clientShare to dstShared. The private key is wiped on return.
func (x *Exchanger) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	if len(dstServerShare) < ShareSize || len(dstShared) < SharedSize {
		return 0, 0, io.ErrShortBuffer
	} else if len(clientShare) != ShareSize {
		return 0, 0, errShareSize
	}
	if err := x.generate(rand); err != nil {
		return 0, 0, err
	}
	defer x.Zeroize()
	if err := x.shared(dstShared, clientShare); err != nil {
		return 0, 0, err
	}
	x25519.ScalarBaseMult((*[32]byte)(dstServerShare), &x.priv)
	return ShareSize, SharedSize, nil
}

// ClientShared writes the secret shared with serverShare to dstShared.
func (x *Exchanger) ClientShared(dstShared, serverShare []byte) (int, error) {
	if len(dstShared) < SharedSize {
		return 0, io.ErrShortBuffer
	} else if len(serverShare) != ShareSize {
		return 0, errShareSize
	} else if !x.keyed {
		return 0, errNoKey
	}
	if err := x.shared(dstShared, serverShare); err != nil {
		return 0, err
	}
	return SharedSize, nil
}

// Zeroize wipes the private key.
func (x *Exchanger) Zeroize() { *x = Exchanger{} }

func (x *Exchanger) generate(rand io.Reader) error {
	x.Zeroize()
	if _, err := io.ReadFull(rand, x.priv[:]); err != nil {
		x.Zeroize()
		return err
	}
	x.keyed = true
	return nil
}

// shared computes X25519 into dst and rejects the all-zero output of low order
// points, RFC 8446 7.4.2.
func (x *Exchanger) shared(dst, peer []byte) error {
	out := (*[32]byte)(dst)
	x25519.ScalarMult(out, &x.priv, (*[32]byte)(peer))
	var acc byte
	for _, b := range out {
		acc |= b
	}
	if acc == 0 {
		return errLowOrder
	}
	return nil
}
