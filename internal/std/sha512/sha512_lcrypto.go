package sha512

// Digest is over TinyGo's stack allocation limit: assigning a composite literal
// with fields set would build a heap temporary, so zero first, then set size.

// Init sets d up to compute SHA-512 without allocating.
func (d *Digest) Init() { d.init(size512) }

// Init384 sets d up to compute SHA-384 without allocating.
func (d *Digest) Init384() { d.init(size384) }

// Zeroize wipes all state, buffered input included, and resets d for reuse
// with the same algorithm. [Digest.Reset] leaves buffered input in place.
func (d *Digest) Zeroize() { d.init(d.size) }

func (d *Digest) init(size int) {
	*d = Digest{}
	d.size = size
	d.Reset()
}
