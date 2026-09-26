package ecdh

// ValidP256PrivateKey reports whether key is a 32 byte big-endian scalar in [1, n-1].
func ValidP256PrivateKey(key []byte) bool {
	return len(key) == len(p256Order) && !isZero(key) && isLess(key, p256Order)
}
