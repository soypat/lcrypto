package x509

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/soypat/lcrypto/internal/std/cryptobyte"
	"github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"
)

// SignatureAlgorithm is a certificate signature algorithm this package can verify.
type SignatureAlgorithm uint8

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota // Any other, SHA-1 and MD5 included.
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
)

// PublicKeyAlgorithm is the type of a certificate's subject public key.
type PublicKeyAlgorithm uint8

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA                                          // Verifiable: PublicKey is the modulus, RSAExponent the exponent.
	ECDSAP256                                    // Verifiable: PublicKey is the uncompressed point.
	ECDSAP224                                    // Parsed, not verifiable.
	ECDSAP384                                    // Parsed, not verifiable.
	ECDSAP521                                    // Parsed, not verifiable.
	Ed25519                                      // Parsed, not verifiable.
	DSA                                          // Parsed, not verifiable.
	MLDSA                                        // Parsed, not verifiable.
)

// KeyUsage is the key usage extension bit set: bit i of the BIT STRING is 1<<i.
type KeyUsage uint16

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// ExtKeyUsage is the set of extended key usages a certificate lists that
// matter to TLS.
type ExtKeyUsage uint8

const (
	ExtKeyUsageAny ExtKeyUsage = 1 << iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageOther // Any usage not above.
)

// Certificate is a view of a parsed DER certificate: its slices share memory
// with the DER passed to [Certificate.Parse], so the DER must outlive it and not
// be modified.
type Certificate struct {
	Raw                     []byte // Complete DER certificate.
	RawTBSCertificate       []byte // Signed part.
	RawIssuer               []byte // DER issuer Name.
	RawSubject              []byte // DER subject Name.
	RawSubjectPublicKeyInfo []byte // DER SubjectPublicKeyInfo.
	Signature               []byte // Issuer's signature over RawTBSCertificate.
	// PublicKey is the RSA modulus (big-endian, no leading zeroes) or the
	// subject public key BIT STRING of other key types.
	PublicKey      []byte
	SubjectKeyId   []byte
	AuthorityKeyId []byte
	// SubjectAltName is the value of the subject alternative name extension:
	// a DER GeneralNames SEQUENCE, validated by Parse.
	SubjectAltName []byte

	NotBefore, NotAfter int64 // Validity in seconds since the Unix epoch.
	RSAExponent         int
	// MaxPathLen is the basic constraints path length, or -1 if absent.
	MaxPathLen int

	Version            uint8 // 1, 2 or 3.
	SignatureAlgorithm SignatureAlgorithm
	PublicKeyAlgorithm PublicKeyAlgorithm
	KeyUsage           KeyUsage
	ExtKeyUsage        ExtKeyUsage // Zero if absent or empty.

	BasicConstraintsValid bool
	IsCA                  bool
	// UnhandledCriticalExtension is set if a critical extension is not
	// processed; such a certificate is never used by a Verifier.
	UnhandledCriticalExtension bool
	// NameConstraints, RequireExplicitPolicy and MapsAnyPolicy are set if the
	// certificate has name constraints, a policy constraint requiring explicit
	// policy or a policy mapping of anyPolicy. A Verifier rejects chains whose
	// CAs carry any, rather than implement the processing they call for.
	NameConstraints       bool
	RequireExplicitPolicy bool
	MapsAnyPolicy         bool
}

// Errors are crypto/x509's parse errors.
var (
	errMalformedCert         = errors.New("x509: malformed certificate")
	errMalformedTBS          = errors.New("x509: malformed tbs certificate")
	errMalformedVersion      = errors.New("x509: malformed version")
	errInvalidVersion        = errors.New("x509: invalid version")
	errMalformedSerial       = errors.New("x509: malformed serial number")
	errNegativeSerial        = errors.New("x509: negative serial number")
	errMalformedSigAlg       = errors.New("x509: malformed signature algorithm identifier")
	errMalformedAlg          = errors.New("x509: malformed algorithm identifier")
	errSigAlgMismatch        = errors.New("x509: inner and outer signature algorithm identifiers don't match")
	errMalformedOID          = errors.New("x509: malformed OID")
	errMalformedParams       = errors.New("x509: malformed parameters")
	errMalformedIssuer       = errors.New("x509: malformed issuer")
	errMalformedValidity     = errors.New("x509: malformed validity")
	errMalformedTime         = errors.New("x509: malformed time")
	errMalformedSPKI         = errors.New("x509: malformed spki")
	errMalformedPKAlg        = errors.New("x509: malformed public key algorithm identifier")
	errMalformedSPK          = errors.New("x509: malformed subjectPublicKey")
	errMalformedUniqueID     = errors.New("x509: malformed unique identifier")
	errMalformedExtensions   = errors.New("x509: malformed extensions")
	errMalformedExtension    = errors.New("x509: malformed extension")
	errDuplicateExtension    = errors.New("x509: certificate contains duplicate extension")
	errMalformedSignature    = errors.New("x509: malformed signature")
	errTrailingData          = errors.New("x509: trailing data")
	errInvalidRDN            = errors.New("x509: invalid RDNSequence")
	errRSAParams             = errors.New("x509: RSA key missing NULL parameters")
	errRSAKey                = errors.New("x509: invalid RSA public key")
	errECParams              = errors.New("x509: invalid ECDSA parameters")
	errECCurve               = errors.New("x509: unsupported elliptic curve")
	errECKey                 = errors.New("x509: invalid ECDSA public key")
	errEd25519Key            = errors.New("x509: invalid Ed25519 public key")
	errDSAKey                = errors.New("x509: invalid DSA public key")
	errMLDSAKey              = errors.New("x509: invalid ML-DSA public key")
	errKeyUsage              = errors.New("x509: invalid key usage")
	errBasicConstraints      = errors.New("x509: invalid basic constraints")
	errSAN                   = errors.New("x509: invalid subject alternative names")
	errAKID                  = errors.New("x509: invalid authority key identifier")
	errSKID                  = errors.New("x509: invalid subject key identifier")
	errEKU                   = errors.New("x509: invalid extended key usages")
	errCRLDP                 = errors.New("x509: invalid CRL distribution points")
	errPolicyConstraints     = errors.New("x509: invalid policy constraints extension")
	errNameConstraints       = errors.New("x509: invalid NameConstraints extension")
	errPolicies              = errors.New("x509: invalid certificate policies")
	errPolicyMappings        = errors.New("x509: invalid policy mappings extension")
	errInhibitAnyPolicy      = errors.New("x509: invalid inhibit any policy extension")
	errAIA                   = errors.New("x509: invalid authority info access")
	errMarkedCritical        = errors.New("x509: extension incorrectly marked critical")
	errTooManyExtensions     = errors.New("x509: too many extensions")
	errUnsupportedSigPadding = errors.New("x509: signature or key BIT STRING not byte aligned")
)

// maxExtensions bounds the quadratic duplicate extension check.
const maxExtensions = 64

// OBJECT IDENTIFIER contents octets.
var (
	oidPublicKeyRSA      = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	oidSignatureRSAPSS   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
	oidSignatureRSA256   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	oidSignatureRSA384   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c}
	oidSignatureRSA512   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d}
	oidMGF1              = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08}
	oidPublicKeyECDSA    = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	oidSignatureECDSA256 = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	oidSignatureECDSA384 = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	oidSignatureECDSA512 = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}
	oidCurveP256         = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	oidCurveP224         = []byte{0x2b, 0x81, 0x04, 0x00, 0x21}
	oidCurveP384         = []byte{0x2b, 0x81, 0x04, 0x00, 0x22}
	oidCurveP521         = []byte{0x2b, 0x81, 0x04, 0x00, 0x23}
	oidPublicKeyEd25519  = []byte{0x2b, 0x65, 0x70}
	oidPublicKeyDSA      = []byte{0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01}
	oidPublicKeyMLDSA    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03} // Followed by 0x11, 0x12 or 0x13.
	oidSHA256            = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSHA384            = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}
	oidSHA512            = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}
	oidAIA               = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01}
	oidEKUServerAuth     = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}
	oidEKUClientAuth     = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}
	oidEKUAny            = []byte{0x55, 0x1d, 0x25, 0x00}
	oidAnyPolicy         = []byte{0x55, 0x1d, 0x20, 0x00}
	asn1NULL             = []byte{0x05, 0x00}
)

// Parse parses the single DER certificate der into c, following crypto/x509's
// ParseCertificate: it rejects the certificates Go rejects, except as noted in
// the package documentation. c references der.
func (c *Certificate) Parse(der []byte) error {
	*c = Certificate{}
	err := c.parse(der)
	if err == nil && len(der) != len(c.Raw) {
		err = errTrailingData
	}
	if err != nil {
		*c = Certificate{}
	}
	return err
}

func (c *Certificate) parse(der []byte) error {
	input := cryptobyte.String(der)
	if !input.ReadASN1Element(&input, asn1.SEQUENCE) {
		return errMalformedCert
	}
	c.Raw = input
	if !input.ReadASN1(&input, asn1.SEQUENCE) {
		return errMalformedCert
	}
	var tbs cryptobyte.String
	if !input.ReadASN1Element(&tbs, asn1.SEQUENCE) {
		return errMalformedTBS
	}
	c.RawTBSCertificate = tbs
	if !tbs.ReadASN1(&tbs, asn1.SEQUENCE) {
		return errMalformedTBS
	}

	var version int
	if !tbs.ReadOptionalASN1Int(&version, asn1.Tag(0).Constructed().ContextSpecific(), 0) || version < 0 {
		return errMalformedVersion
	}
	if version > 2 {
		return errInvalidVersion
	}
	c.Version = uint8(version) + 1

	var serial cryptobyte.String
	if !tbs.ReadASN1(&serial, asn1.INTEGER) || !validInteger(serial) {
		return errMalformedSerial
	}
	if serial[0]&0x80 != 0 {
		return errNegativeSerial
	}

	var sigAISeq cryptobyte.String
	if !tbs.ReadASN1Element(&sigAISeq, asn1.SEQUENCE) || !sigAISeq.ReadASN1(&sigAISeq, asn1.SEQUENCE) {
		return errMalformedSigAlg
	}
	var outerSigAISeq cryptobyte.String
	if !input.ReadASN1(&outerSigAISeq, asn1.SEQUENCE) {
		return errMalformedAlg
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return errSigAlgMismatch
	}
	sigOID, sigParams, err := parseAI(sigAISeq)
	if err != nil {
		return err
	}
	c.SignatureAlgorithm = signatureAlgorithm(sigOID, sigParams)

	var issuer cryptobyte.String
	if !tbs.ReadASN1Element(&issuer, asn1.SEQUENCE) {
		return errMalformedIssuer
	}
	c.RawIssuer = issuer
	if err := validateName(issuer); err != nil {
		return err
	}

	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, asn1.SEQUENCE) {
		return errMalformedValidity
	}
	if !readASN1Time(&validity, &c.NotBefore) || !readASN1Time(&validity, &c.NotAfter) {
		return errMalformedTime
	}

	var subject cryptobyte.String
	if !tbs.ReadASN1Element(&subject, asn1.SEQUENCE) {
		return errMalformedIssuer
	}
	c.RawSubject = subject
	if err := validateName(subject); err != nil {
		return err
	}

	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, asn1.SEQUENCE) {
		return errMalformedSPKI
	}
	c.RawSubjectPublicKeyInfo = spki
	if !spki.ReadASN1(&spki, asn1.SEQUENCE) {
		return errMalformedSPKI
	}
	var pkAISeq cryptobyte.String
	if !spki.ReadASN1(&pkAISeq, asn1.SEQUENCE) {
		return errMalformedPKAlg
	}
	pkOID, pkParams, err := parseAI(pkAISeq)
	if err != nil {
		return err
	}
	var spk []byte
	var padding uint8
	if !spki.ReadASN1BitStringBytes(&spk, &padding) {
		return errMalformedSPK
	}
	if err := c.parsePublicKey(pkOID, pkParams, spk, padding); err != nil {
		return err
	}

	if c.Version > 1 {
		if !tbs.SkipOptionalASN1(asn1.Tag(1).ContextSpecific()) ||
			!tbs.SkipOptionalASN1(asn1.Tag(2).ContextSpecific()) {
			return errMalformedUniqueID
		}
		if c.Version == 3 {
			var extensions cryptobyte.String
			var present bool
			if !tbs.ReadOptionalASN1(&extensions, &present, asn1.Tag(3).Constructed().ContextSpecific()) {
				return errMalformedExtensions
			}
			if present {
				if err := c.parseExtensions(extensions); err != nil {
					return err
				}
			}
		}
	}

	if !input.ReadASN1BitStringBytes(&c.Signature, &padding) {
		return errMalformedSignature
	}
	if padding != 0 {
		// Go right-aligns such a signature; no valid signature needs it.
		return errUnsupportedSigPadding
	}
	return nil
}

// validInteger is cryptobyte's checkASN1Integer: non-empty and minimally encoded.
func validInteger(b []byte) bool {
	return len(b) == 1 || len(b) > 1 && !(b[0] == 0 && b[1]&0x80 == 0 || b[0] == 0xff && b[1]&0x80 != 0)
}

// parseAI returns the algorithm OID and the full parameters element, if any.
func parseAI(der cryptobyte.String) (oid, params []byte, err error) {
	if !der.ReadASN1ObjectIdentifierBytes(&oid) {
		return nil, nil, errMalformedOID
	}
	if der.Empty() {
		return oid, nil, nil
	}
	var p cryptobyte.String
	var tag asn1.Tag
	if !der.ReadAnyASN1Element(&p, &tag) {
		return nil, nil, errMalformedParams
	}
	return oid, p, nil
}

func readASN1Time(der *cryptobyte.String, out *int64) bool {
	switch {
	case der.PeekASN1Tag(asn1.UTCTime):
		return der.ReadASN1UTCTimeUnix(out)
	case der.PeekASN1Tag(asn1.GeneralizedTime):
		return der.ReadASN1GeneralizedTimeUnix(out)
	}
	return false
}

// signatureAlgorithm is getSignatureAlgorithmFromAI restricted to the
// algorithms this package verifies.
func signatureAlgorithm(oid, params []byte) SignatureAlgorithm {
	switch {
	case bytes.Equal(oid, oidSignatureRSA256):
		return SHA256WithRSA
	case bytes.Equal(oid, oidSignatureRSA384):
		return SHA384WithRSA
	case bytes.Equal(oid, oidSignatureRSA512):
		return SHA512WithRSA
	case bytes.Equal(oid, oidSignatureECDSA256):
		return ECDSAWithSHA256
	case bytes.Equal(oid, oidSignatureECDSA384):
		return ECDSAWithSHA384
	case bytes.Equal(oid, oidSignatureECDSA512):
		return ECDSAWithSHA512
	case bytes.Equal(oid, oidSignatureRSAPSS):
		return pssAlgorithm(params)
	}
	return UnknownSignatureAlgorithm
}

// pssAlgorithm reads RSASSA-PSS-params. Like Go it accepts only MGF1 with the
// message hash, a salt as long as the hash and the default trailer field.
//
//	RSASSA-PSS-params ::= SEQUENCE {
//	  hashAlgorithm    [0] HashAlgorithm,
//	  maskGenAlgorithm [1] MaskGenAlgorithm,
//	  saltLength       [2] INTEGER,
//	  trailerField     [3] INTEGER DEFAULT 1 }
func pssAlgorithm(params cryptobyte.String) SignatureAlgorithm {
	var seq, hashAI, mgfAI, mgfHashAI cryptobyte.String
	var hashOID, mgfOID, mgfHashOID []byte
	var salt int
	trailer := 1
	if !params.ReadASN1(&seq, asn1.SEQUENCE) ||
		!seq.ReadASN1(&hashAI, asn1.Tag(0).Constructed().ContextSpecific()) ||
		!hashAI.ReadASN1(&hashAI, asn1.SEQUENCE) ||
		!hashAI.ReadASN1ObjectIdentifierBytes(&hashOID) || !nullOrEmpty(hashAI) ||
		!seq.ReadASN1(&mgfAI, asn1.Tag(1).Constructed().ContextSpecific()) ||
		!mgfAI.ReadASN1(&mgfAI, asn1.SEQUENCE) ||
		!mgfAI.ReadASN1ObjectIdentifierBytes(&mgfOID) || !bytes.Equal(mgfOID, oidMGF1) ||
		!mgfAI.ReadASN1(&mgfHashAI, asn1.SEQUENCE) || !mgfAI.Empty() ||
		!mgfHashAI.ReadASN1ObjectIdentifierBytes(&mgfHashOID) || !nullOrEmpty(mgfHashAI) ||
		!bytes.Equal(mgfHashOID, hashOID) ||
		!seq.ReadOptionalASN1Int(&salt, asn1.Tag(2).Constructed().ContextSpecific(), -1) ||
		!seq.ReadOptionalASN1Int(&trailer, asn1.Tag(3).Constructed().ContextSpecific(), 1) ||
		!seq.Empty() || trailer != 1 {
		return UnknownSignatureAlgorithm
	}
	switch {
	case bytes.Equal(hashOID, oidSHA256) && salt == 32:
		return SHA256WithRSAPSS
	case bytes.Equal(hashOID, oidSHA384) && salt == 48:
		return SHA384WithRSAPSS
	case bytes.Equal(hashOID, oidSHA512) && salt == 64:
		return SHA512WithRSAPSS
	}
	return UnknownSignatureAlgorithm
}

// nullOrEmpty reports whether the rest of an AlgorithmIdentifier holds
// absent or NULL parameters.
func nullOrEmpty(s cryptobyte.String) bool { return s.Empty() || bytes.Equal(s, asn1NULL) }

// validateName checks a DER Name as parseName does, without building it.
func validateName(raw cryptobyte.String) error {
	if !raw.ReadASN1(&raw, asn1.SEQUENCE) {
		return errInvalidRDN
	}
	for !raw.Empty() {
		var set cryptobyte.String
		if !raw.ReadASN1(&set, asn1.SET) {
			return errInvalidRDN
		}
		for !set.Empty() {
			var atav cryptobyte.String
			var oid []byte
			if !set.ReadASN1(&atav, asn1.SEQUENCE) ||
				!atav.ReadASN1ObjectIdentifierBytes(&oid) ||
				!validASN1Any(&atav) {
				return errInvalidRDN
			}
		}
	}
	return nil
}

const (
	tagBMPString     = asn1.Tag(30)
	tagNumericString = asn1.Tag(18)
)

// validASN1Any reports whether readASN1Any would parse the next element.
func validASN1Any(der *cryptobyte.String) bool {
	var full cryptobyte.String
	var tag asn1.Tag
	if !der.ReadAnyASN1Element(&full, &tag) {
		return false
	}
	var v []byte
	var i64 int64
	var b bool
	var padding uint8
	switch tag {
	case asn1.T61String, asn1.PrintableString, asn1.UTF8String, tagBMPString, asn1.IA5String, tagNumericString:
		return full.ReadASN1((*cryptobyte.String)(&v), tag) && validASN1String(tag, v)
	case asn1.INTEGER:
		return full.ReadASN1Int64(&i64)
	case asn1.BIT_STRING:
		return full.ReadASN1BitStringBytes(&v, &padding)
	case asn1.OBJECT_IDENTIFIER:
		return full.ReadASN1ObjectIdentifierBytes(&v)
	case asn1.UTCTime, asn1.GeneralizedTime:
		return readASN1Time(&full, &i64)
	case asn1.BOOLEAN:
		return full.ReadASN1Boolean(&b)
	}
	return true // OCTET STRING, NULL and any other element.
}

// validASN1String is parseASN1String's validation.
func validASN1String(tag asn1.Tag, v []byte) bool {
	switch tag {
	case asn1.PrintableString:
		for _, c := range v {
			if !isPrintable(c) {
				return false
			}
		}
	case asn1.UTF8String:
		return utf8.Valid(v)
	case tagBMPString:
		if len(v)%2 != 0 {
			return false
		}
		if l := len(v); l >= 2 && v[l-1] == 0 && v[l-2] == 0 {
			v = v[:l-2]
		}
		for ; len(v) > 0; v = v[2:] {
			p := uint16(v[0])<<8 | uint16(v[1])
			if p == 0xfffe || p == 0xffff || p >= 0xfdd0 && p <= 0xfdef || p >= 0xd800 && p <= 0xdfff {
				return false
			}
		}
	case asn1.IA5String:
		return isIA5(v)
	case tagNumericString:
		for _, c := range v {
			if !('0' <= c && c <= '9' || c == ' ') {
				return false
			}
		}
	}
	return true // T61String: any bytes, read as Latin-1.
}

// isPrintable is crypto/x509's, which admits '*' and '&' seen in the wild.
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' || b == ':' || b == '=' || b == '?' || b == '*' || b == '&'
}

func isIA5(v []byte) bool {
	for _, c := range v {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// parsePublicKey is parsePublicKey's validation. Elliptic curve points are
// checked for length and form only: a Verifier checks P-256 points when it
// uses them, and cannot use other curves.
func (c *Certificate) parsePublicKey(oid, params, data []byte, padding uint8) error {
	switch {
	case bytes.Equal(oid, oidPublicKeyRSA):
		if !bytes.Equal(params, asn1NULL) {
			return errRSAParams
		}
		der := cryptobyte.String(data)
		var n []byte
		var e int64
		if padding != 0 || !der.ReadASN1(&der, asn1.SEQUENCE) ||
			!der.ReadASN1IntegerBytes(&n) || !der.ReadASN1Int64(&e) ||
			isZero(n) || e <= 0 || int64(int(e)) != e {
			return errRSAKey
		}
		c.PublicKeyAlgorithm, c.PublicKey, c.RSAExponent = RSA, n, int(e)
	case bytes.Equal(oid, oidPublicKeyECDSA):
		p := cryptobyte.String(params)
		var curve []byte
		if !p.ReadASN1ObjectIdentifierBytes(&curve) {
			return errECParams
		}
		var size int
		switch {
		case bytes.Equal(curve, oidCurveP256):
			c.PublicKeyAlgorithm, size = ECDSAP256, 32
		case bytes.Equal(curve, oidCurveP224):
			c.PublicKeyAlgorithm, size = ECDSAP224, 28
		case bytes.Equal(curve, oidCurveP384):
			c.PublicKeyAlgorithm, size = ECDSAP384, 48
		case bytes.Equal(curve, oidCurveP521):
			c.PublicKeyAlgorithm, size = ECDSAP521, 66
		default:
			return errECCurve
		}
		if padding != 0 || len(data) != 1+2*size || data[0] != 4 {
			return errECKey
		}
		c.PublicKey = data
	case bytes.Equal(oid, oidPublicKeyEd25519):
		if len(params) != 0 || padding != 0 || len(data) != 32 {
			return errEd25519Key
		}
		c.PublicKeyAlgorithm, c.PublicKey = Ed25519, data
	case len(oid) == len(oidPublicKeyMLDSA)+1 && bytes.HasPrefix(oid, oidPublicKeyMLDSA) &&
		oid[len(oid)-1] >= 0x11 && oid[len(oid)-1] <= 0x13:
		size := [...]int{1312, 1952, 2592}[oid[len(oid)-1]-0x11]
		if len(params) != 0 || padding != 0 || len(data) != size {
			return errMLDSAKey
		}
		c.PublicKeyAlgorithm, c.PublicKey = MLDSA, data
	case bytes.Equal(oid, oidPublicKeyDSA):
		// RightAlign of a padded BIT STRING would shift the key; no DSA key needs it.
		y := cryptobyte.String(data)
		p := cryptobyte.String(params)
		var yv, pv, qv, gv []byte
		if padding != 0 || !y.ReadASN1IntegerBytes(&yv) ||
			!p.ReadASN1(&p, asn1.SEQUENCE) ||
			!p.ReadASN1IntegerBytes(&pv) || !p.ReadASN1IntegerBytes(&qv) || !p.ReadASN1IntegerBytes(&gv) ||
			isZero(yv) || isZero(pv) || isZero(qv) || isZero(gv) {
			return errDSAKey
		}
		c.PublicKeyAlgorithm, c.PublicKey = DSA, data
	}
	return nil // Unknown algorithms are not parsed, as in Go.
}

func isZero(b []byte) bool { return len(b) == 1 && b[0] == 0 }

func (c *Certificate) parseExtensions(exts cryptobyte.String) error {
	if !exts.ReadASN1(&exts, asn1.SEQUENCE) {
		return errMalformedExtensions
	}
	all := exts
	for n := 0; !exts.Empty(); n++ {
		if n == maxExtensions {
			return errTooManyExtensions
		}
		var ext cryptobyte.String
		var oid []byte
		var critical bool
		var value cryptobyte.String
		if !exts.ReadASN1(&ext, asn1.SEQUENCE) {
			return errMalformedExtension
		}
		if !ext.ReadASN1ObjectIdentifierBytes(&oid) ||
			ext.PeekASN1Tag(asn1.BOOLEAN) && !ext.ReadASN1Boolean(&critical) ||
			!ext.ReadASN1(&value, asn1.OCTET_STRING) {
			return errMalformedExtension
		}
		// Duplicates: compare with the OIDs of the extensions before this one.
		prev := all
		for i := 0; i < n; i++ {
			var e cryptobyte.String
			var o []byte
			prev.ReadASN1(&e, asn1.SEQUENCE)
			e.ReadASN1ObjectIdentifierBytes(&o)
			if bytes.Equal(o, oid) {
				return errDuplicateExtension
			}
		}
		unhandled, err := c.processExtension(oid, critical, value)
		if err != nil {
			return err
		}
		if critical && unhandled {
			c.UnhandledCriticalExtension = true
		}
	}
	return nil
}

// processExtension is processExtensions for one extension.
func (c *Certificate) processExtension(oid []byte, critical bool, val cryptobyte.String) (unhandled bool, err error) {
	if !(len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x1d) {
		if !bytes.Equal(oid, oidAIA) {
			return true, nil
		}
		if critical {
			return false, errMarkedCritical
		}
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errAIA
		}
		for !val.Empty() {
			var aia cryptobyte.String
			var method []byte
			if !val.ReadASN1(&aia, asn1.SEQUENCE) || !aia.ReadASN1ObjectIdentifierBytes(&method) {
				return false, errAIA
			}
			if aia.PeekASN1Tag(asn1.Tag(6).ContextSpecific()) && !aia.ReadASN1(&aia, asn1.Tag(6).ContextSpecific()) {
				return false, errAIA
			}
		}
		return false, nil
	}

	switch oid[2] {
	case 15: // Key usage.
		var bits []byte
		var padding uint8
		if !val.ReadASN1BitStringBytes(&bits, &padding) {
			return false, errKeyUsage
		}
		nbits := len(bits)*8 - int(padding)
		for i := 0; i < 9 && i < nbits; i++ {
			if bits[i/8]&(0x80>>(i%8)) != 0 {
				c.KeyUsage |= 1 << i
			}
		}

	case 19: // Basic constraints.
		c.MaxPathLen = -1
		var mpl uint
		if !val.ReadASN1(&val, asn1.SEQUENCE) ||
			val.PeekASN1Tag(asn1.BOOLEAN) && !val.ReadASN1Boolean(&c.IsCA) {
			return false, errBasicConstraints
		}
		if val.PeekASN1Tag(asn1.INTEGER) {
			if !val.ReadASN1Uint(&mpl) || int(mpl) < 0 {
				return false, errBasicConstraints
			}
			c.MaxPathLen = int(mpl)
		}
		c.BasicConstraintsValid = true

	case 17: // Subject alternative name.
		names, err := validateSAN(val)
		if err != nil {
			return false, err
		}
		c.SubjectAltName = val
		unhandled = names == 0

	case 30: // Name constraints; see Certificate.NameConstraints.
		c.NameConstraints = true
		return nameConstraintsUnhandled(val)

	case 31: // CRL distribution points.
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errCRLDP
		}
		for !val.Empty() {
			var dp, name cryptobyte.String
			var present bool
			if !val.ReadASN1(&dp, asn1.SEQUENCE) ||
				!dp.ReadOptionalASN1(&name, &present, asn1.Tag(0).Constructed().ContextSpecific()) {
				return false, errCRLDP
			}
			if !present {
				continue
			}
			if !name.ReadASN1(&name, asn1.Tag(0).Constructed().ContextSpecific()) {
				return false, errCRLDP
			}
			for name.PeekASN1Tag(asn1.Tag(6).ContextSpecific()) {
				var uri cryptobyte.String
				if !name.ReadASN1(&uri, asn1.Tag(6).ContextSpecific()) {
					return false, errCRLDP
				}
			}
		}

	case 35: // Authority key identifier.
		if critical {
			return false, errMarkedCritical
		}
		var akid cryptobyte.String
		if !val.ReadASN1(&akid, asn1.SEQUENCE) {
			return false, errAKID
		}
		if akid.PeekASN1Tag(asn1.Tag(0).ContextSpecific()) {
			if !akid.ReadASN1(&akid, asn1.Tag(0).ContextSpecific()) {
				return false, errAKID
			}
			c.AuthorityKeyId = akid
		}

	case 36: // Policy constraints.
		var v int64
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errPolicyConstraints
		}
		if val.PeekASN1Tag(asn1.Tag(0).ContextSpecific()) {
			if !val.ReadASN1Int64WithTag(&v, asn1.Tag(0).ContextSpecific()) || int64(int(v)) != v {
				return false, errPolicyConstraints
			}
			c.RequireExplicitPolicy = true
		}
		if val.PeekASN1Tag(asn1.Tag(1).ContextSpecific()) {
			if !val.ReadASN1Int64WithTag(&v, asn1.Tag(1).ContextSpecific()) || int64(int(v)) != v {
				return false, errPolicyConstraints
			}
		}

	case 37: // Extended key usage.
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errEKU
		}
		for !val.Empty() {
			var eku []byte
			if !val.ReadASN1ObjectIdentifierBytes(&eku) {
				return false, errEKU
			}
			switch {
			case bytes.Equal(eku, oidEKUAny):
				c.ExtKeyUsage |= ExtKeyUsageAny
			case bytes.Equal(eku, oidEKUServerAuth):
				c.ExtKeyUsage |= ExtKeyUsageServerAuth
			case bytes.Equal(eku, oidEKUClientAuth):
				c.ExtKeyUsage |= ExtKeyUsageClientAuth
			default:
				c.ExtKeyUsage |= ExtKeyUsageOther
			}
		}

	case 14: // Subject key identifier.
		if critical {
			return false, errMarkedCritical
		}
		var skid cryptobyte.String
		if !val.ReadASN1(&skid, asn1.OCTET_STRING) {
			return false, errSKID
		}
		c.SubjectKeyId = skid

	case 32: // Certificate policies: well formed, no duplicates.
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errPolicies
		}
		all := val
		for n := 0; !val.Empty(); n++ {
			var cp, oid cryptobyte.String
			if !val.ReadASN1(&cp, asn1.SEQUENCE) || !cp.ReadASN1(&oid, asn1.OBJECT_IDENTIFIER) || !validOID(oid) {
				return false, errPolicies
			}
			prev := all
			for i := 0; i < n; i++ {
				var p, o cryptobyte.String
				prev.ReadASN1(&p, asn1.SEQUENCE)
				p.ReadASN1(&o, asn1.OBJECT_IDENTIFIER)
				if bytes.Equal(o, oid) {
					return false, errPolicies
				}
			}
		}

	case 33: // Policy mappings.
		if !val.ReadASN1(&val, asn1.SEQUENCE) {
			return false, errPolicyMappings
		}
		for !val.Empty() {
			var s, issuer, subject cryptobyte.String
			if !val.ReadASN1(&s, asn1.SEQUENCE) ||
				!s.ReadASN1(&issuer, asn1.OBJECT_IDENTIFIER) ||
				!s.ReadASN1(&subject, asn1.OBJECT_IDENTIFIER) {
				return false, errPolicyMappings
			}
			if bytes.Equal(issuer, oidAnyPolicy) || bytes.Equal(subject, oidAnyPolicy) {
				c.MapsAnyPolicy = true
			}
		}

	case 54: // Inhibit anyPolicy.
		var v int
		if !val.ReadASN1Int(&v) {
			return false, errInhibitAnyPolicy
		}

	default:
		return true, nil
	}
	return false, nil
}

// nameConstraintsUnhandled is parseNameConstraintsExtension's structure check:
// constraints on names other than DNS, IP, email and URI are unhandled. The
// constraint values are not validated.
//
//	NameConstraints ::= SEQUENCE {
//	     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
//	     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
//	GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
//	GeneralSubtree ::= SEQUENCE { base GeneralName, ... }
func nameConstraintsUnhandled(outer cryptobyte.String) (unhandled bool, err error) {
	var top, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&top, asn1.SEQUENCE) || !outer.Empty() ||
		!top.ReadOptionalASN1(&permitted, &havePermitted, asn1.Tag(0).ContextSpecific().Constructed()) ||
		!top.ReadOptionalASN1(&excluded, &haveExcluded, asn1.Tag(1).ContextSpecific().Constructed()) ||
		!top.Empty() || len(permitted) == 0 && len(excluded) == 0 {
		return false, errNameConstraints
	}
	for _, subtrees := range [2]cryptobyte.String{permitted, excluded} {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag asn1.Tag
			if !subtrees.ReadASN1(&seq, asn1.SEQUENCE) || !seq.ReadAnyASN1(&value, &tag) {
				return false, errNameConstraints
			}
			switch tag ^ 0x80 {
			case nameTypeEmail, nameTypeDNS, nameTypeURI, nameTypeIP:
			default:
				unhandled = true
			}
		}
	}
	return unhandled, nil
}

// validOID is newOIDFromDER's check: base 128 components of any size, each
// minimally encoded and complete.
func validOID(der []byte) bool {
	if len(der) == 0 || der[len(der)-1]&0x80 != 0 {
		return false
	}
	start := true
	for _, b := range der {
		if start && b == 0x80 {
			return false
		}
		start = b&0x80 == 0
	}
	return true
}

// GeneralName tags of subject alternative names.
const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// validateSAN is parseSANExtension's validation. It returns the number of
// email, DNS, URI and IP names. URIs are checked to be IA5 strings only: Go
// additionally rejects those net/url cannot parse.
func validateSAN(der cryptobyte.String) (names int, err error) {
	if !der.ReadASN1(&der, asn1.SEQUENCE) {
		return 0, errSAN
	}
	for !der.Empty() {
		var data cryptobyte.String
		var tag asn1.Tag
		if !der.ReadAnyASN1(&data, &tag) {
			return 0, errSAN
		}
		switch tag ^ 0x80 {
		case nameTypeEmail, nameTypeDNS, nameTypeURI:
			if !isIA5(data) {
				return 0, errSAN
			}
		case nameTypeIP:
			if len(data) != 4 && (len(data) != 16 || isV4Mapped(data)) {
				return 0, errSAN
			}
		default:
			continue
		}
		names++
	}
	return names, nil
}

// isV4Mapped reports whether the 16 byte ip is ::ffff:a.b.c.d, which
// net.IP.To4 converts.
func isV4Mapped(ip []byte) bool {
	for _, b := range ip[:10] {
		if b != 0 {
			return false
		}
	}
	return ip[10] == 0xff && ip[11] == 0xff
}

// sanIter iterates the GeneralNames of a SubjectAltName validated by Parse.
type sanIter struct{ der cryptobyte.String }

func (it *sanIter) init(san []byte) {
	it.der = san
	it.der.ReadASN1(&it.der, asn1.SEQUENCE)
}

// next returns the next name's context-specific tag number and contents.
func (it *sanIter) next() (tag int, data []byte, ok bool) {
	var t asn1.Tag
	if !it.der.ReadAnyASN1((*cryptobyte.String)(&data), &t) {
		return 0, nil, false
	}
	return int(t ^ 0x80), data, true
}
