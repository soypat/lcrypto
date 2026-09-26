package aes

// InitBlock expands key into b without allocating. b is wiped first so that no
// round keys of a previous, longer key survive.
func InitBlock(b *Block, key []byte) error {
	*b = Block{}
	switch len(key) {
	case aes128KeySize, aes192KeySize, aes256KeySize:
	default:
		return KeySizeError(len(key))
	}
	newBlock(b, key)
	return nil
}
