package nistec

import (
	"errors"
	"io"
)

var (
	errPrivateKey = errors.New("ecdsa: invalid private key")
	errNoKey      = errors.New("ecdsa: no private key set")
	errRZero      = errors.New("ecdsa: internal error: r is zero")
	errSZero      = errors.New("ecdsa: internal error: s is zero")
)

var p256Ord ordModulus

func init() {
	n := [p256ElementLength]byte{
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
	}
	p256Ord.init(n[:])
}

// signState is the curve independent part of ECDSA signing, following
// crypto/internal/fips140/ecdsa: Sign (hedged) and SignDeterministic (RFC 6979)
// seed an HMAC_DRBG from which signGeneric draws the nonce k, then
//
//	r = x(k·G) mod n, s = k⁻¹·(e + r·d) mod n.
//
// Secrets are handled with constant time arithmetic and wiped after use.
type signState struct {
	d       ordElem
	dBytes  [ordLimbs * 8]byte
	hasKey  bool
	drbg    hmacDRBG
	k, kInv ordElem
	e, r, s ordElem
	kBytes  [ordLimbs * 8]byte
	eBytes  [ordLimbs * 8]byte
	z       [ordLimbs * 8]byte
	hashBuf [ordLimbs * 8]byte
}

// setKey sets the private key d, big-endian of at most m.size bytes.
func (st *signState) setKey(m *ordModulus, d []byte) error {
	st.wipeKey()
	if !m.setCanonical(&st.d, d) {
		st.wipeKey()
		return errPrivateKey
	}
	m.putBytes(st.dBytes[:m.size], &st.d)
	st.hasKey = true
	return nil
}

// begin seeds the DRBG: hedged with SHA-512 and entropy from rand, or
// deterministic with detHash if rand is nil.
func (st *signState) begin(m *ordModulus, hash []byte, rand io.Reader, detHash uint8) error {
	if !st.hasKey {
		return errNoKey
	}
	if len(hash) == 0 {
		return errEmptyHash
	}
	m.hashToScalar(&st.e, hash, &st.hashBuf)
	m.putBytes(st.eBytes[:m.size], &st.e) // bits2octets
	d := st.dBytes[:m.size]
	if rand == nil {
		st.drbg.init(detHash, d, st.eBytes[:m.size], nil, nil, false)
		return nil
	}
	if _, err := io.ReadFull(rand, st.z[:m.size]); err != nil {
		return err
	}
	st.drbg.init(HashSHA512, st.z[:m.size], nil, d, st.eBytes[:m.size], true)
	return nil
}

// nextK draws a nonce candidate into st.k and st.kBytes and reports whether it
// is in [1, n-1], as randomPoint. Orders here are whole bytes: no shift.
func (st *signState) nextK(m *ordModulus) bool {
	st.drbg.generate(st.kBytes[:m.size])
	return m.setCanonical(&st.k, st.kBytes[:m.size])
}

// finish computes the signature from rx, the x coordinate of k·G, into rOut
// and sOut, m.size bytes each, and wipes the per signature secrets.
func (st *signState) finish(m *ordModulus, rx, rOut, sOut []byte) error {
	err := st.compute(m, rx, rOut, sOut)
	st.wipe() // Not deferred: TinyGo heap allocates deferred calls.
	return err
}

func (st *signState) compute(m *ordModulus, rx, rOut, sOut []byte) error {
	m.setOverflowing(&st.r, rx)
	if m.isZero(&st.r) {
		return errRZero
	}
	m.inverse(&st.kInv, &st.k)
	m.mul(&st.s, &st.d, &st.r)
	m.add(&st.s, &st.s, &st.e)
	m.mul(&st.s, &st.s, &st.kInv)
	if m.isZero(&st.s) {
		return errSZero
	}
	m.putBytes(rOut, &st.r)
	m.putBytes(sOut, &st.s)
	return nil
}

// wipe clears the per signature state, keeping the key.
func (st *signState) wipe() {
	st.drbg.wipe()
	st.k, st.kInv, st.e, st.r, st.s = ordElem{}, ordElem{}, ordElem{}, ordElem{}, ordElem{}
	clear(st.kBytes[:])
	clear(st.eBytes[:])
	clear(st.z[:])
	clear(st.hashBuf[:])
}

func (st *signState) wipeKey() {
	st.wipe()
	st.d = ordElem{}
	clear(st.dBytes[:])
	st.hasKey = false
}

// P256Signer signs with a P-256 private key. The generator is multiplied with
// the window method of ScalarMult rather than ScalarBaseMult, so signing does
// not need the 88 KiB generator table.
type P256Signer struct {
	st    signState
	p     P256Point
	table p256Table
	rx    [p256ElementLength]byte
}

// SetKey sets the private key, big-endian of at most 32 bytes, in [1, n-1].
func (s *P256Signer) SetKey(d []byte) error { return s.st.setKey(&p256Ord, d) }

// PublicKeyTo writes the uncompressed public key into out.
func (s *P256Signer) PublicKeyTo(out *[p256UncompressedLength]byte) ([]byte, error) {
	if !s.st.hasKey {
		return nil, errNoKey
	}
	p256Ord.putBytes(s.st.kBytes[:32], &s.st.d)
	s.p.SetGenerator()
	_, err := s.p.scalarMult(&s.p, s.st.kBytes[:32], &s.table)
	clear(s.st.kBytes[:])
	if err != nil {
		return nil, err
	}
	return s.p.BytesTo(out), nil
}

// Sign writes the signature (r, s) of hash, 32 bytes each. If rand is nil the
// signature is deterministic (RFC 6979) with HMAC over detHash.
func (s *P256Signer) Sign(hash []byte, rand io.Reader, detHash uint8, r, sig *[p256ElementLength]byte) error {
	st := &s.st
	if err := st.begin(&p256Ord, hash, rand, detHash); err != nil {
		st.wipe()
		return err
	}
	for !st.nextK(&p256Ord) {
	}
	s.p.SetGenerator()
	if _, err := s.p.scalarMult(&s.p, st.kBytes[:32], &s.table); err != nil {
		st.wipe()
		return err
	}
	rx, err := s.p.BytesXTo(&s.rx)
	if err != nil {
		st.wipe()
		return err
	}
	return st.finish(&p256Ord, rx, r[:], sig[:])
}

// Zeroize wipes the key and all state.
func (s *P256Signer) Zeroize() { *s = P256Signer{} }

// P384Signer signs with a P-384 private key.
type P384Signer struct {
	st    signState
	p     P384Point
	table p384Table
	rx    [p384ElementLength]byte
}

// SetKey sets the private key, big-endian of at most 48 bytes, in [1, n-1].
func (s *P384Signer) SetKey(d []byte) error { return s.st.setKey(&p384Ord, d) }

// PublicKeyTo writes the uncompressed public key into out.
func (s *P384Signer) PublicKeyTo(out *[1 + 2*p384ElementLength]byte) ([]byte, error) {
	if !s.st.hasKey {
		return nil, errNoKey
	}
	p384Ord.putBytes(s.st.kBytes[:48], &s.st.d)
	s.p.SetGenerator()
	_, err := s.p.scalarMult(&s.p, s.st.kBytes[:48], &s.table)
	clear(s.st.kBytes[:])
	if err != nil {
		return nil, err
	}
	return s.p.BytesTo(out), nil
}

// Sign writes the signature (r, s) of hash, 48 bytes each. If rand is nil the
// signature is deterministic (RFC 6979) with HMAC over detHash.
func (s *P384Signer) Sign(hash []byte, rand io.Reader, detHash uint8, r, sig *[p384ElementLength]byte) error {
	st := &s.st
	if err := st.begin(&p384Ord, hash, rand, detHash); err != nil {
		st.wipe()
		return err
	}
	for !st.nextK(&p384Ord) {
	}
	s.p.SetGenerator()
	if _, err := s.p.scalarMult(&s.p, st.kBytes[:48], &s.table); err != nil {
		st.wipe()
		return err
	}
	rx, err := s.p.BytesXTo(&s.rx)
	if err != nil {
		st.wipe()
		return err
	}
	return st.finish(&p384Ord, rx, r[:], sig[:])
}

// Zeroize wipes the key and all state.
func (s *P384Signer) Zeroize() { *s = P384Signer{} }
