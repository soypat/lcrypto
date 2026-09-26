package sha256

// Init sets d up to compute SHA-256 without allocating.
func (d *Digest) Init() { d.init(false) }

// Init224 sets d up to compute SHA-224 without allocating.
func (d *Digest) Init224() { d.init(true) }

// Zeroize wipes all state, buffered input included, and resets d for reuse
// with the same algorithm. [Digest.Reset] leaves buffered input in place.
func (d *Digest) Zeroize() { d.init(d.is224) }

func (d *Digest) init(is224 bool) {
	*d = Digest{}
	d.is224 = is224
	d.Reset()
}
