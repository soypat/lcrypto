package x509

var (
	ParseIP    = parseIP
	RawSubject = rawSubject
)

// Stricter reports whether err is a rejection by one of this package's
// policies stricter than crypto/x509's.
func Stricter(err error) bool {
	switch err {
	case errLeafKeyUsage, errWeakRSA, errExtraData, errEmptyRDN, errEmptyIssuer, errEmptySubject, errEmptyEKU, errUnsupportedSigPadding, errTooManyExtensions:
		return true
	}
	return false
}

var (
	ErrExtraData    = errExtraData
	ErrEmptyRDN     = errEmptyRDN
	ErrEmptyIssuer  = errEmptyIssuer
	ErrEmptySubject = errEmptySubject
	ErrEmptyEKU     = errEmptyEKU
)
