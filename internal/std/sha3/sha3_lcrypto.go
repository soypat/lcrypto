package sha3

// Init256 sets d up to compute SHA3-256 without allocating.
func (d *Digest) Init256() { d.init(rateK512, 32, dsbyteSHA3) }

// Init512 sets d up to compute SHA3-512 without allocating.
func (d *Digest) Init512() { d.init(rateK1024, 64, dsbyteSHA3) }

func (d *Digest) init(rate, outputLen int, dsbyte byte) {
	*d = Digest{}
	d.rate, d.outputLen, d.dsbyte = rate, outputLen, dsbyte
}

// Zeroize wipes all state and resets d for reuse with the same function.
func (d *Digest) Zeroize() { d.init(d.rate, d.outputLen, d.dsbyte) }

// InitShake128 sets s up as a SHAKE128 XOF without allocating.
func (s *SHAKE) InitShake128() { *s = SHAKE{}; s.d.init(rateK256, 32, dsbyteShake) }

// InitShake256 sets s up as a SHAKE256 XOF without allocating.
func (s *SHAKE) InitShake256() { *s = SHAKE{}; s.d.init(rateK512, 64, dsbyteShake) }
