package edwards25519

// Scratch is the working memory of the Scratch methods: the window tables that
// upstream keeps as locals or precomputes for the base point.
type Scratch struct {
	a, b nafLookupTable5
}

// ScalarBaseMultScratch is [Point.ScalarBaseMult] with its table in s.
func (v *Point) ScalarBaseMultScratch(x *Scalar, s *Scratch) *Point {
	return v.scalarMult(x, generator, (*projLookupTable)(&s.a))
}

// ScalarMultScratch is [Point.ScalarMult] with its table in s.
func (v *Point) ScalarMultScratch(x *Scalar, q *Point, s *Scratch) *Point {
	return v.scalarMult(x, q, (*projLookupTable)(&s.a))
}

// VarTimeDoubleScalarBaseMultScratch is [Point.VarTimeDoubleScalarBaseMult]
// with its tables in s.
func (v *Point) VarTimeDoubleScalarBaseMultScratch(a *Scalar, A *Point, b *Scalar, s *Scratch) *Point {
	return v.varTimeDoubleScalarBaseMult(a, A, b, &s.a, &s.b)
}
