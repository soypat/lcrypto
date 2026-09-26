package x509

var (
	ParseIP    = parseIP
	RawSubject = rawSubject
)

// Stricter reports whether err is a rejection by one of Verifier's policies
// stricter than crypto/x509's.
func Stricter(err error) bool { return err == errLeafKeyUsage || err == errWeakRSA }
