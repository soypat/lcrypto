// Package x509 parses X.509 certificates and verifies TLS peers with them,
// without heap allocation.
//
// [Certificate.Parse] follows crypto/x509's ParseCertificate, rejecting what it
// rejects, but builds a view: fields are slices of the DER. It differs in that it
// does not check URI names parse as URLs, the contents of name constraints (any
// name constraints make a CA unusable to [Verifier] instead), that elliptic curve
// points are on their curve (a Verifier checks P-256 points when it uses them),
// and it rejects signatures and keys with unused BIT STRING bits and certificates
// with more than 64 extensions.
//
// [Verifier] implements [lcrypto.Verifier] after crypto/x509's Verify and
// crypto/tls's TLS 1.3 CertificateVerify check.
package x509

import (
	"io"

	"github.com/soypat/lcrypto"
)

// Chain is an in-memory [lcrypto.CertChain] of DER certificates, leaf first.
type Chain [][]byte

var _ lcrypto.CertChain = Chain(nil)

// NumCerts implements [lcrypto.CertChain].
func (c Chain) NumCerts() int { return len(c) }

// Cert implements [lcrypto.CertChain].
func (c Chain) Cert(dst []byte, i int) (int, error) {
	if i < 0 || i >= len(c) {
		return 0, errIndex
	}
	if len(dst) < len(c[i]) {
		return len(c[i]), io.ErrShortBuffer
	}
	return copy(dst, c[i]), nil
}

// CertView implements [lcrypto.CertChain].
func (c Chain) CertView(i int) ([]byte, error) {
	if i < 0 || i >= len(c) {
		return nil, errIndex
	}
	return c[i], nil
}
