package nistec

// p384Ord is arithmetic modulo the order of the P-384 group.
var p384Ord ordModulus

func init() {
	n := [p384ElementLength]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
		0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
	}
	p384Ord.init(n[:])
}

// P384VerifyScratch is the working memory of [P384Verify], about 2.5 KiB.
type P384VerifyScratch struct {
	p1     P384Point
	table  p384Table
	scalar [p384ElementLength]byte
	rx     [p384ElementLength]byte
	hash   [ordLimbs * 8]byte
}

// P384Verify checks the ECDSA signature (r, s) of hash by public key q, which it
// overwrites. It follows crypto/internal/fips140/ecdsa.verifyGeneric, with
// [ordModulus] in place of bigmod and the generator multiplied by ScalarMult,
// the generator table being too large:
//
//	w = s⁻¹, u1 = e·w, u2 = r·w (mod n); valid if x(u1·G + u2·Q) ≡ r (mod n).
//
// r and s are big-endian without leading zeroes, as read from ASN.1.
func P384Verify(q *P384Point, hash, r, s []byte, sc *P384VerifyScratch) error {
	return verifyOrd(&p384Ord, q, hash, r, s, sc)
}

func verifyOrd(m *ordModulus, q *P384Point, hash, r, s []byte, sc *P384VerifyScratch) error {
	if len(hash) == 0 {
		return errEmptyHash
	}
	var rs, ss, e, w, u ordElem
	if !m.setCanonical(&rs, r) || !m.setCanonical(&ss, s) {
		return errSigRange
	}
	m.hashToScalar(&e, hash, &sc.hash)
	m.inverse(&w, &ss)

	m.mul(&u, &e, &w) // u1
	m.putBytes(sc.scalar[:], &u)
	sc.p1.SetGenerator()
	if _, err := sc.p1.scalarMult(&sc.p1, sc.scalar[:], &sc.table); err != nil {
		return err
	}
	m.mul(&u, &rs, &w) // u2
	m.putBytes(sc.scalar[:], &u)
	if _, err := q.scalarMult(q, sc.scalar[:], &sc.table); err != nil {
		return err
	}
	rx, err := sc.p1.Add(&sc.p1, q).BytesXTo(&sc.rx)
	if err != nil {
		return err
	}
	var v ordElem
	m.setOverflowing(&v, rx) // x < p < 2n.
	if v != rs {
		return errSigVerify
	}
	return nil
}
