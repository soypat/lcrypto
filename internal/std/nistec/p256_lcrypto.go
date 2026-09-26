package nistec

// P256Scratch is the working memory of [P256Point.ScalarMultScratch].
type P256Scratch struct{ table p256Table }

// ScalarMultScratch is [P256Point.ScalarMult] with its window table in s instead of the heap.
func (p *P256Point) ScalarMultScratch(q *P256Point, scalar []byte, s *P256Scratch) (*P256Point, error) {
	return p.scalarMult(q, scalar, &s.table)
}
