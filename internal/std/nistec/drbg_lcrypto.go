package nistec

import (
	"github.com/soypat/lcrypto/internal/std/sha256"
	"github.com/soypat/lcrypto/internal/std/sha512"
)

// HMAC hash functions of [hmacDRBG].
const (
	HashSHA256 = iota + 1
	HashSHA384
	HashSHA512
)

// hmacDRBG is crypto/internal/fips140/ecdsa's HMAC_DRBG (SP 800-90A Rev. 1),
// transcribed to hold its HMAC and buffers in place: the key is at most the
// hash size, which is at most the block size, so HMAC needs no key hashing.
type hmacDRBG struct {
	h256        sha256.Digest
	h512        sha512.Digest
	hash        uint8
	size, block int
	k, v        [64]byte
	pad         [128]byte // HMAC key xor ipad or opad.
	sum         [64]byte
	zeros       [128]byte
	one         [1]byte
}

func (d *hmacDRBG) hInit() {
	switch d.hash {
	case HashSHA256:
		d.h256.Init()
	case HashSHA384:
		d.h512.Init384()
	default:
		d.h512.Init()
	}
}

func (d *hmacDRBG) write(b []byte) {
	if d.hash == HashSHA256 {
		d.h256.Write(b)
	} else {
		d.h512.Write(b)
	}
}

func (d *hmacDRBG) hSum() {
	if d.hash == HashSHA256 {
		d.h256.Sum(d.sum[:0])
	} else {
		d.h512.Sum(d.sum[:0])
	}
}

func (d *hmacDRBG) keyPad(xor byte) {
	for i := range d.pad[:d.block] {
		var k byte
		if i < d.size {
			k = d.k[i]
		}
		d.pad[i] = k ^ xor
	}
}

// macStart starts HMAC keyed with d.k; macEnd writes it into out.
func (d *hmacDRBG) macStart() {
	d.keyPad(0x36)
	d.hInit()
	d.write(d.pad[:d.block])
}

func (d *hmacDRBG) macEnd(out []byte) {
	d.hSum()
	d.keyPad(0x5c)
	d.hInit()
	d.write(d.pad[:d.block])
	d.write(d.sum[:d.size])
	d.hSum()
	copy(out, d.sum[:d.size])
}

// pad000 writes zeros up to a block boundary after writtenSoFar bytes.
func (d *hmacDRBG) pad000(writtenSoFar int) {
	if rem := writtenSoFar % d.block; rem != 0 {
		d.write(d.zeros[:d.block-rem])
	}
}

// init is newDRBG. If blockAligned, pers1 and pers2 are the entries of a
// blockAlignedPersonalizationString; otherwise there is no personalization.
func (d *hmacDRBG) init(hash uint8, entropy, nonce, pers1, pers2 []byte, blockAligned bool) {
	d.hash = hash
	switch hash {
	case HashSHA256:
		d.size, d.block = 32, 64
	case HashSHA384:
		d.size, d.block = 48, 128
	default:
		d.hash, d.size, d.block = HashSHA512, 64, 128
	}
	d.one[0] = 1
	clear(d.k[:])
	for i := range d.v[:d.size] {
		d.v[i] = 1
	}
	for _, sep := range [2]int{0, 1} {
		// K = HMAC(K, V || sep || entropy || nonce || personalization)
		d.macStart()
		d.write(d.v[:d.size])
		if sep == 0 {
			d.write(d.zeros[:1])
		} else {
			d.write(d.one[:])
		}
		d.write(entropy)
		d.write(nonce)
		if blockAligned {
			l := d.size + 1 + len(entropy) + len(nonce)
			d.pad000(l)
			d.write(pers1)
			d.pad000(len(pers1))
			d.write(pers2)
		}
		d.macEnd(d.k[:])
		// V = HMAC(K, V)
		d.macStart()
		d.write(d.v[:d.size])
		d.macEnd(d.v[:])
	}
}

// generate is Generate: it fills out, of at most a few hash sizes.
func (d *hmacDRBG) generate(out []byte) {
	for n := 0; n < len(out); {
		d.macStart()
		d.write(d.v[:d.size])
		d.macEnd(d.v[:])
		n += copy(out[n:], d.v[:d.size])
	}
	d.macStart()
	d.write(d.v[:d.size])
	d.write(d.zeros[:1])
	d.macEnd(d.k[:])
	d.macStart()
	d.write(d.v[:d.size])
	d.macEnd(d.v[:])
}

// wipe clears the secret state.
func (d *hmacDRBG) wipe() {
	d.h256 = sha256.Digest{}
	d.h512 = sha512.Digest{}
	clear(d.k[:])
	clear(d.v[:])
	clear(d.pad[:])
	clear(d.sum[:])
}
