package cryptobyte

// ReadASN1IntegerBytes is ReadASN1Integer for a *[]byte out: it reads a
// non-negative ASN.1 INTEGER as big-endian bytes without leading zeroes, sharing
// memory with s. It avoids ReadASN1Integer's interface parameter.
func (s *String) ReadASN1IntegerBytes(out *[]byte) bool { return s.readASN1Bytes(out) }
