package bigmod

import "errors"

var errModulusSize = errors.New("bigmod: modulus larger than MaxBits")

// InitModulus sets m to the big-endian modulus b like [NewModulus], keeping all
// of its storage inside m. b must not exceed MaxBits once leading zeroes are removed.
func InitModulus(m *Modulus, b []byte) error {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) > MaxBits/8 {
		return errModulusSize
	}
	*m = Modulus{}
	m.nat = m.natStore.resetToBytes(b)
	if m.nat.IsZero() == yes || m.nat.IsOne() == yes {
		return errModulusTooSmall
	}
	if m.nat.IsOdd() == 1 {
		m.odd = true
		m.m0inv = minusInverseModW(m.nat.lim()[0])
		m.rr = rr(m)
	}
	return nil
}

var errModulusTooSmall = errors.New("modulus must be > 1")

// FillBytes writes x as a zero-extended big-endian number into out, which must
// be m.Size() bytes long. It is the allocation-free [Nat.Bytes].
func (x *Nat) FillBytes(out []byte, m *Modulus) {
	if len(out) != m.Size() {
		panic("bigmod: FillBytes output of wrong size")
	}
	i := len(out)
	clear(out)
	for _, limb := range x.lim() {
		for j := 0; j < _S; j++ {
			i--
			if i < 0 {
				if limb == 0 {
					break
				}
				panic("bigmod: modulus is smaller than nat")
			}
			out[i] = byte(limb)
			limb >>= 8
		}
	}
}
