// Package p256 implements ECDH over NIST P-256, TLS 1.3 group secp256r1 (0x0017),
// as an [lcrypto.Exchanger]. Key shares are uncompressed points, RFC 8446 4.2.8.2.
//
// The implementation is the Go standard library's generic (pure Go) nistec, ported
// by lcryptogen. Its 88 KiB precomputed base point table is a writable variable,
// and so on microcontrollers occupies RAM.
package p256

import (
	"errors"
	"io"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/internal/std/ecdh"
	"github.com/soypat/lcrypto/internal/std/nistec"
)

var _ lcrypto.Exchanger = (*Exchanger)(nil)

const (
	GroupID    = 0x0017 // RFC 8446 4.2.7 NamedGroup secp256r1.
	ShareSize  = 65     // Uncompressed point: 0x04 || X || Y.
	SharedSize = 32     // X coordinate of the shared point.
	// maxDraws bounds rejection sampling of the private key. A draw is rejected
	// with probability about 2⁻³², so hitting the bound means rand is broken.
	maxDraws = 8
)

var (
	errShareSize = errors.New("p256: key share must be a 65 byte uncompressed point")
	errBadRand   = errors.New("p256: rand produced no valid private key")
	errNoKey     = errors.New("p256: ClientShared before ClientGenerateRekey")
)

// Exchanger is P-256 ephemeral Diffie-Hellman. Its zero value is ready for use.
// Exchanger is not safe for concurrent use.
type Exchanger struct {
	priv    [32]byte
	point   nistec.P256Point
	scratch nistec.P256Scratch
	keyed   bool
}

// ClientGenerateRekey draws a private key from rand and writes the public key to dstClientShare.
func (x *Exchanger) ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (int, error) {
	if len(dstClientShare) < ShareSize {
		return 0, io.ErrShortBuffer
	}
	if err := x.generate(rand); err != nil {
		return 0, err
	}
	x.public(dstClientShare)
	return ShareSize, nil
}

// ServerSharedRekey draws a private key from rand, writes its public key to dstServerShare
// and the secret shared with clientShare to dstShared. Secret state is wiped on return.
func (x *Exchanger) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	if len(dstServerShare) < ShareSize || len(dstShared) < SharedSize {
		return 0, 0, io.ErrShortBuffer
	}
	if err := x.generate(rand); err != nil {
		return 0, 0, err
	}
	defer x.Zeroize()
	if err := x.shared(dstShared, clientShare); err != nil {
		return 0, 0, err
	}
	x.public(dstServerShare)
	return ShareSize, SharedSize, nil
}

// ClientShared writes the secret shared with serverShare to dstShared.
func (x *Exchanger) ClientShared(dstShared, serverShare []byte) (int, error) {
	if len(dstShared) < SharedSize {
		return 0, io.ErrShortBuffer
	} else if !x.keyed {
		return 0, errNoKey
	}
	if err := x.shared(dstShared, serverShare); err != nil {
		return 0, err
	}
	return SharedSize, nil
}

// Zeroize wipes the private key and scratch space.
func (x *Exchanger) Zeroize() { *x = Exchanger{} }

// generate draws a private key in [1, n-1] by rejection sampling, as crypto/ecdh does.
func (x *Exchanger) generate(rand io.Reader) error {
	x.Zeroize()
	for range maxDraws {
		if _, err := io.ReadFull(rand, x.priv[:]); err != nil {
			x.Zeroize()
			return err
		}
		if ecdh.ValidP256PrivateKey(x.priv[:]) {
			x.keyed = true
			return nil
		}
	}
	x.Zeroize()
	return errBadRand
}

func (x *Exchanger) public(dst []byte) {
	if _, err := x.point.ScalarBaseMult(x.priv[:]); err != nil {
		panic("p256: ScalarBaseMult of a valid private key failed")
	}
	x.point.BytesTo((*[ShareSize]byte)(dst))
}

// shared computes the x coordinate of priv·peer. SetBytes checks peer is on the curve.
func (x *Exchanger) shared(dst, peer []byte) error {
	if len(peer) != ShareSize || peer[0] != 4 {
		return errShareSize
	}
	if _, err := x.point.SetBytes(peer); err != nil {
		return err
	}
	if _, err := x.point.ScalarMultScratch(&x.point, x.priv[:], &x.scratch); err != nil {
		return err
	}
	_, err := x.point.BytesXTo((*[SharedSize]byte)(dst))
	return err
}
