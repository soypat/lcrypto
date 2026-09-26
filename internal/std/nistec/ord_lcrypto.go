package nistec

import "math/bits"

// ordLimbs is the number of 64-bit limbs of the largest curve order supported,
// P-521's.
const ordLimbs = 9

// ordElem is a number modulo a curve order, little-endian in 64-bit limbs.
type ordElem [ordLimbs]uint64

// ordModulus is arithmetic modulo a curve order n in Montgomery form, with
// R = 2^(64·limbs). It is constant time in the values of its operands, which
// signing needs for the private key and nonce; only n is public.
type ordModulus struct {
	n       ordElem
	nMinus2 ordElem
	rr      ordElem // R² mod n.
	n0inv   uint64  // -n⁻¹ mod 2⁶⁴.
	limbs   int
	size    int // Bytes.
	bitLen  int
}

// init sets m to arithmetic modulo the odd big-endian n.
func (m *ordModulus) init(n []byte) {
	m.size = len(n)
	m.limbs = (len(n) + 7) / 8
	m.setBytes(&m.n, n)
	m.bitLen = 64*(m.limbs-1) + bits.Len64(m.n[m.limbs-1])
	m.nMinus2 = m.n
	m.nMinus2[0] -= 2 // n is odd and large: no borrow.
	inv := uint64(1)
	for i := 0; i < 6; i++ { // Newton iteration doubles the correct bits.
		inv *= 2 - m.n[0]*inv
	}
	m.n0inv = -inv
	// R² mod n by doubling 1 modulo n.
	var r ordElem
	r[0] = 1
	for i := 0; i < 2*64*m.limbs; i++ {
		var carry uint64
		for j := 0; j < m.limbs; j++ {
			r[j], carry = r[j]<<1|carry, r[j]>>63
		}
		m.reduceOnce(&r, carry)
	}
	m.rr = r
}

// setBytes sets x to the big-endian b, of at most m.size bytes.
func (m *ordModulus) setBytes(x *ordElem, b []byte) {
	*x = ordElem{}
	for i, c := range b {
		k := len(b) - 1 - i
		x[k/8] |= uint64(c) << (8 * (k % 8))
	}
}

// putBytes writes x big-endian into out, m.size bytes long.
func (m *ordModulus) putBytes(out []byte, x *ordElem) {
	for i := range out[:m.size] {
		k := m.size - 1 - i
		out[i] = byte(x[k/8] >> (8 * (k % 8)))
	}
}

// less reports whether x < n, in constant time.
func (m *ordModulus) less(x *ordElem) bool {
	var borrow uint64
	for i := 0; i < m.limbs; i++ {
		_, borrow = bits.Sub64(x[i], m.n[i], borrow)
	}
	return borrow == 1
}

// isZero reports whether x is zero, in constant time.
func (m *ordModulus) isZero(x *ordElem) bool {
	var acc uint64
	for i := 0; i < m.limbs; i++ {
		acc |= x[i]
	}
	return acc == 0
}

// reduceOnce sets x = x - n if carry·2^(64·limbs) + x >= n, in constant time.
// carry is 0 or 1 and the value must be below 2n.
func (m *ordModulus) reduceOnce(x *ordElem, carry uint64) {
	var d ordElem
	var borrow uint64
	for i := 0; i < m.limbs; i++ {
		d[i], borrow = bits.Sub64(x[i], m.n[i], borrow)
	}
	// Keep d unless the subtraction borrowed without a carry to absorb it.
	keep := -(carry | (borrow ^ 1)) // All ones to take d.
	for i := 0; i < m.limbs; i++ {
		x[i] = d[i]&keep | x[i]&^keep
	}
}

// setCanonical sets x to the big-endian b and reports whether it is in
// [1, n-1], as bigmod.Nat.SetBytes followed by the IsZero check.
func (m *ordModulus) setCanonical(x *ordElem, b []byte) bool {
	if len(b) > m.size {
		return false
	}
	m.setBytes(x, b)
	return m.less(x) && !m.isZero(x)
}

// setOverflowing sets x to the big-endian b reduced modulo n, as
// bigmod.Nat.SetOverflowingBytes: b may be at most as long as n in bits.
func (m *ordModulus) setOverflowing(x *ordElem, b []byte) bool {
	if len(b) > m.size {
		return false
	}
	m.setBytes(x, b)
	top := m.limbs - 1
	if 64*top+bits.Len64(x[top]) > m.bitLen {
		return false
	}
	m.reduceOnce(x, 0) // x < 2^bitLen < 2n.
	return true
}

// hashToScalar is ecdsa's hashToNat: the leftmost bitLen bits of hash, reduced.
// buf holds the shifted hash for orders whose bit length is not a multiple of 8.
func (m *ordModulus) hashToScalar(x *ordElem, hash []byte, buf *[ordLimbs * 8]byte) {
	if len(hash) >= m.size {
		hash = hash[:m.size]
		if excess := len(hash)*8 - m.bitLen; excess > 0 {
			h := buf[:len(hash)]
			copy(h, hash)
			for i := len(h) - 1; i >= 0; i-- {
				h[i] >>= excess
				if i > 0 {
					h[i] |= h[i-1] << (8 - excess)
				}
			}
			hash = h
		}
	}
	m.setOverflowing(x, hash) // Cannot fail: hash fits bitLen.
}

// montMul sets z = x·y·R⁻¹ mod n for x, y < n. z may alias x or y.
func (m *ordModulus) montMul(z, x, y *ordElem) {
	var t [ordLimbs + 2]uint64
	L := m.limbs
	for i := 0; i < L; i++ {
		// t += x·y[i]
		var c uint64
		for j := 0; j < L; j++ {
			hi, lo := bits.Mul64(x[j], y[i])
			var cc uint64
			lo, cc = bits.Add64(lo, t[j], 0)
			hi += cc
			lo, cc = bits.Add64(lo, c, 0)
			hi += cc
			t[j], c = lo, hi
		}
		var cc uint64
		t[L], cc = bits.Add64(t[L], c, 0)
		t[L+1] = cc
		// t = (t + n·(t[0]·n0inv mod 2⁶⁴)) / 2⁶⁴
		q := t[0] * m.n0inv
		hi, lo := bits.Mul64(q, m.n[0])
		_, cc = bits.Add64(lo, t[0], 0)
		c = hi + cc
		for j := 1; j < L; j++ {
			hi, lo := bits.Mul64(q, m.n[j])
			lo, cc = bits.Add64(lo, t[j], 0)
			hi += cc
			lo, cc = bits.Add64(lo, c, 0)
			hi += cc
			t[j-1], c = lo, hi
		}
		t[L-1], cc = bits.Add64(t[L], c, 0)
		t[L] = t[L+1] + cc
	}
	var r ordElem
	copy(r[:L], t[:L])
	m.reduceOnce(&r, t[L])
	*z = r
}

// add sets z = x + y mod n for x, y < n.
func (m *ordModulus) add(z, x, y *ordElem) {
	var r ordElem
	var carry uint64
	for i := 0; i < m.limbs; i++ {
		r[i], carry = bits.Add64(x[i], y[i], carry)
	}
	m.reduceOnce(&r, carry)
	*z = r
}

// mul sets z = x·y mod n: Mont(x)·y·R⁻¹ = x·y.
func (m *ordModulus) mul(z, x, y *ordElem) {
	var xm ordElem
	m.montMul(&xm, x, &m.rr)
	m.montMul(z, &xm, y)
}

// inverse sets z = x⁻¹ mod n = x^(n-2) for x in [1, n-1]. The exponent is
// public, so the square and multiply chain leaks nothing about x.
func (m *ordModulus) inverse(z, x *ordElem) {
	var xm, r, one ordElem
	one[0] = 1
	m.montMul(&xm, x, &m.rr)
	m.montMul(&r, &one, &m.rr) // R mod n: one in Montgomery form.
	for i := m.bitLen - 1; i >= 0; i-- {
		m.montMul(&r, &r, &r)
		if m.nMinus2[i/64]>>(i%64)&1 != 0 {
			m.montMul(&r, &r, &xm)
		}
	}
	m.montMul(z, &r, &one)
}
