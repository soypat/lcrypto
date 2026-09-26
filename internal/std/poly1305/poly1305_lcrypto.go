package poly1305

// Init keys h in place with a one-time key. It is the allocation-free counterpart of [New].
func (h *MAC) Init(key *[32]byte) {
	*h = MAC{}
	initialize(key, &h.macState)
}
