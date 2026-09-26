package subtle

// XORInto sets dst[i] ^= src[i] for i < n = min(len(dst), len(src)) and returns n.
// Unlike [XORBytes] it does no overlap check, whose pointer to integer conversion
// makes TinyGo heap allocate every buffer passed in.
func XORInto(dst, src []byte) int {
	n := min(len(dst), len(src))
	dst, src = dst[:n], src[:n]
	for i := range dst {
		dst[i] ^= src[i]
	}
	return n
}
