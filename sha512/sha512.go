// Package sha512 implements SHA-512 and SHA-384 of FIPS 180-4 as a [hash.Hash]
// that can be embedded by value and wiped with Zeroize.
//
// The implementation is the Go standard library's generic (pure Go) code, ported by lcryptogen.
package sha512

import (
	"hash"

	"github.com/soypat/lcrypto/internal/std/sha512"
)

const (
	Size      = 64  // SHA-512 checksum length in bytes.
	Size384   = 48  // SHA-384 checksum length in bytes.
	BlockSize = 128 // Block size of SHA-512 and SHA-384 in bytes.
)

// Digest is a SHA-512 or SHA-384 hash state. Its zero value is not ready for use:
// call [Digest.Init] or [Digest.Init384] first, or use [New] or [New384].
// [Digest.Zeroize] wipes all state and leaves the Digest ready for reuse.
type Digest = sha512.Digest

var _ hash.Hash = (*Digest)(nil)

// New returns a SHA-512 Digest. Declare a Digest and call [Digest.Init] to avoid the allocation.
func New() *Digest {
	d := new(Digest)
	d.Init()
	return d
}

// New384 returns a SHA-384 Digest. Declare a Digest and call [Digest.Init384] to avoid the allocation.
func New384() *Digest {
	d := new(Digest)
	d.Init384()
	return d
}
