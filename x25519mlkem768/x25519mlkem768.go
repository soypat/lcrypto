// Package x25519mlkem768 implements the hybrid key exchange X25519MLKEM768
// (0x11EC) of draft-ietf-tls-ecdhe-mlkem as an [lcrypto.Exchanger]: ML-KEM-768
// and X25519 run side by side, ML-KEM first in every share and in the secret.
//
// The memory and stack notes of package mlkem apply.
package x25519mlkem768

import (
	"errors"
	"io"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/mlkem"
	"github.com/soypat/lcrypto/x25519"
)

var _ lcrypto.Exchanger = (*Exchanger)(nil)

var errShareSize = errors.New("x25519mlkem768: key share of wrong length")

const (
	GroupID         = 0x11EC
	ClientShareSize = mlkem.ClientShareSize768 + x25519.ShareSize
	ServerShareSize = mlkem.ServerShareSize768 + x25519.ShareSize
	SharedSize      = mlkem.SharedSize + x25519.SharedSize
)

// Exchanger is X25519MLKEM768. Its zero value is ready for use. Exchanger is
// not safe for concurrent use.
type Exchanger struct {
	kem mlkem.Exchanger768
	dh  x25519.Exchanger
}

// ClientGenerateRekey writes the ML-KEM-768 encapsulation key followed by the X25519 public key.
func (x *Exchanger) ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (int, error) {
	if len(dstClientShare) < ClientShareSize {
		return 0, io.ErrShortBuffer
	}
	n, err := x.kem.ClientGenerateRekey(dstClientShare, rand)
	if err == nil {
		_, err = x.dh.ClientGenerateRekey(dstClientShare[n:], rand)
	}
	if err != nil {
		x.Zeroize()
		return 0, err
	}
	return ClientShareSize, nil
}

// ServerSharedRekey writes the ML-KEM-768 ciphertext followed by the X25519 public key,
// and the ML-KEM shared secret followed by the X25519 one.
func (x *Exchanger) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	if len(dstServerShare) < ServerShareSize || len(dstShared) < SharedSize {
		return 0, 0, io.ErrShortBuffer
	} else if len(clientShare) != ClientShareSize {
		return 0, 0, errShareSize
	}
	defer x.Zeroize()
	ns, nk, err := x.kem.ServerSharedRekey(dstServerShare, dstShared, clientShare[:mlkem.ClientShareSize768], rand)
	if err != nil {
		return 0, 0, err
	}
	_, _, err = x.dh.ServerSharedRekey(dstServerShare[ns:], dstShared[nk:], clientShare[mlkem.ClientShareSize768:], rand)
	if err != nil {
		clear(dstShared[:SharedSize])
		return 0, 0, err
	}
	return ServerShareSize, SharedSize, nil
}

// ClientShared writes the ML-KEM shared secret followed by the X25519 one.
func (x *Exchanger) ClientShared(dstShared, serverShare []byte) (int, error) {
	if len(dstShared) < SharedSize {
		return 0, io.ErrShortBuffer
	} else if len(serverShare) != ServerShareSize {
		return 0, errShareSize
	}
	nk, err := x.kem.ClientShared(dstShared, serverShare[:mlkem.ServerShareSize768])
	if err == nil {
		_, err = x.dh.ClientShared(dstShared[nk:], serverShare[mlkem.ServerShareSize768:])
	}
	if err != nil {
		clear(dstShared[:SharedSize])
		return 0, err
	}
	return SharedSize, nil
}

// Zeroize wipes both key exchanges.
func (x *Exchanger) Zeroize() {
	x.kem.Zeroize()
	x.dh.Zeroize()
}
