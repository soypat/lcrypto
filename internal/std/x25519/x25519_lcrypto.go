// Package x25519 is the X25519 function of RFC 7748, ported from crypto/ecdh.
package x25519

// ScalarMult sets dst to X25519(scalar, point). scalar is clamped internally.
func ScalarMult(dst, scalar, point *[32]byte) {
	x25519ScalarMult(dst[:], scalar[:], point[:])
}

// ScalarBaseMult sets dst to X25519(scalar, 9), the public key of scalar.
func ScalarBaseMult(dst, scalar *[32]byte) {
	basepoint := [32]byte{9}
	x25519ScalarMult(dst[:], scalar[:], basepoint[:])
}
