// Package sha256 implements SHA-256 and SHA-224 of FIPS 180-4 as a [hash.Hash]
// that can be embedded by value and wiped with Zeroize.
//
// The implementation is the Go standard library's generic (pure Go) code, ported by lcryptogen.
package sha256

import (
	"hash"

	"github.com/soypat/lcrypto/internal/std/sha256"
)

const (
	Size      = 32 // SHA-256 checksum length in bytes.
	Size224   = 28 // SHA-224 checksum length in bytes.
	BlockSize = 64 // Block size of SHA-256 and SHA-224 in bytes.
)

// Digest is a SHA-256 or SHA-224 hash state. Its zero value is not ready for use:
// call [Digest.Init] or [Digest.Init224] first, or use [New].
// [Digest.Zeroize] wipes all state and leaves the Digest ready for reuse.
type Digest = sha256.Digest

var _ hash.Hash = (*Digest)(nil)

// New returns a SHA-256 Digest. Declare a Digest and call [Digest.Init] to avoid the allocation.
func New() *Digest {
	d := new(Digest)
	d.Init()
	return d
}
