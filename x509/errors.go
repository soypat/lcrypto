package x509

//go:generate stringer -type=errX509 -linecomment -output stringers.go

// errX509 is every error of this package, as lneto's errGeneric: comparable
// with ==, and returned without allocating. Verifier returns no other errors,
// so a TLS implementation can always tell the peer why with [errX509.Alert].
type errX509 uint8

const (
	_ errX509 = iota // x509: unknown error
	// Exported: verification failures callers tell apart.
	ErrUnknownAuthority  // x509: certificate signed by unknown authority
	ErrExpired           // x509: certificate has expired or is not yet valid
	ErrIncompatibleUsage // x509: certificate specifies an incompatible key usage
	ErrUnsupported       // x509: unsupported certificate chain feature
	ErrScheme            // x509: signature scheme does not suit the certificate key
	ErrHostname          // x509: certificate is not valid for the expected name

	// Verifier configuration and chain.
	errNoRoots              // x509: Verifier has no roots
	errNotConfigured        // x509: Verifier not configured
	errNoClock              // x509: VerifierConfig.Nanotime required
	errWeakRSA              // x509: RSA key smaller than VerifierConfig.MinRSABits
	errLeafKeyUsage         // x509: leaf key usage does not allow digital signatures
	errRootParse            // x509: root certificate does not parse
	errLimit                // x509: VerifierConfig limit out of range
	errIndex                // x509: certificate index out of range
	errNoName               // x509: expected name required
	errChainLen             // x509: peer sent too many certificates
	errUnhandledCritical    // x509: unhandled critical extension
	errNotAuthorized        // x509: certificate is not authorized to sign other certificates
	errTooManyIntermediates // x509: too many intermediates for path length constraint
	errConstraint           // x509: invalid signature: parent certificate cannot sign this kind of certificate
	errSignatureAlgorithm   // x509: cannot verify signature: algorithm unimplemented
	errKeyMismatch          // x509: signature algorithm does not match the public key
	errSignatureLimit       // x509: signature check attempts limit reached while verifying certificate chain
	errNoCerts              // x509: peer sent no certificates
	errCertView             // x509: peer certificate chain unreadable
	errCertSignature        // x509: certificate signature invalid
	errCertificateVerify    // x509: CertificateVerify signature invalid

	// Credential configuration and signing.
	errKeyDER       // x509: failed to parse EC private key
	errKeyCurve     // x509: private key curve does not match the certificate
	errKeyPublic    // x509: private key does not match the certificate public key
	errLeafKey      // x509: certificate key is not ECDSA P-256, P-384 or Ed25519
	errNoCredential // x509: Credential has no key
	errSignScheme   // x509: signature scheme not offered by the Credential

	// Certificate.Parse.
	errMalformedCert         // x509: malformed certificate
	errMalformedTBS          // x509: malformed tbs certificate
	errMalformedVersion      // x509: malformed version
	errInvalidVersion        // x509: invalid version
	errMalformedSerial       // x509: malformed serial number
	errNegativeSerial        // x509: negative serial number
	errMalformedSigAlg       // x509: malformed signature algorithm identifier
	errMalformedAlg          // x509: malformed algorithm identifier
	errSigAlgMismatch        // x509: inner and outer signature algorithm identifiers don't match
	errMalformedOID          // x509: malformed OID
	errMalformedParams       // x509: malformed parameters
	errMalformedIssuer       // x509: malformed issuer
	errMalformedValidity     // x509: malformed validity
	errMalformedTime         // x509: malformed time
	errMalformedSPKI         // x509: malformed spki
	errMalformedPKAlg        // x509: malformed public key algorithm identifier
	errMalformedSPK          // x509: malformed subjectPublicKey
	errMalformedUniqueID     // x509: malformed unique identifier
	errMalformedExtensions   // x509: malformed extensions
	errMalformedExtension    // x509: malformed extension
	errDuplicateExtension    // x509: certificate contains duplicate extension
	errMalformedSignature    // x509: malformed signature
	errTrailingData          // x509: trailing data
	errInvalidRDN            // x509: invalid RDNSequence
	errRSAParams             // x509: RSA key missing NULL parameters
	errRSAKey                // x509: invalid RSA public key
	errECParams              // x509: invalid ECDSA parameters
	errECCurve               // x509: unsupported elliptic curve
	errECKey                 // x509: invalid ECDSA public key
	errEd25519Key            // x509: invalid Ed25519 public key
	errDSAKey                // x509: invalid DSA public key
	errMLDSAKey              // x509: invalid ML-DSA public key
	errKeyUsage              // x509: invalid key usage
	errBasicConstraints      // x509: invalid basic constraints
	errSAN                   // x509: invalid subject alternative names
	errAKID                  // x509: invalid authority key identifier
	errSKID                  // x509: invalid subject key identifier
	errEKU                   // x509: invalid extended key usages
	errCRLDP                 // x509: invalid CRL distribution points
	errPolicyConstraints     // x509: invalid policy constraints extension
	errNameConstraints       // x509: invalid NameConstraints extension
	errPolicies              // x509: invalid certificate policies
	errPolicyMappings        // x509: invalid policy mappings extension
	errInhibitAnyPolicy      // x509: invalid inhibit any policy extension
	errAIA                   // x509: invalid authority info access
	errMarkedCritical        // x509: extension incorrectly marked critical
	errTooManyExtensions     // x509: too many extensions
	errUnsupportedSigPadding // x509: signature or key BIT STRING not byte aligned
)

func (err errX509) Error() string { return err.String() }

// Alert returns the RFC 8446 6.2 alert description that reports err to the
// peer, as crypto/tls reports crypto/x509 errors: unknown_ca, certificate_expired,
// unsupported_certificate or bad_certificate for a rejected chain,
// illegal_parameter or decrypt_error for a CertificateVerify that does not
// verify, and internal_error for local misconfiguration. TLS implementations
// reach it through an interface{ Alert() uint8 } assertion.
func (err errX509) Alert() uint8 {
	switch err {
	case ErrUnknownAuthority:
		return 48 // unknown_ca
	case ErrExpired:
		return 45 // certificate_expired
	case ErrUnsupported:
		return 43 // unsupported_certificate
	case ErrScheme:
		return 47 // illegal_parameter
	case errCertificateVerify:
		return 51 // decrypt_error
	case errNoCerts:
		return 116 // certificate_required
	case errNoRoots, errNotConfigured, errNoClock, errRootParse, errLimit, errIndex, errNoName, errCertView,
		errKeyDER, errKeyCurve, errKeyPublic, errLeafKey, errNoCredential, errSignScheme:
		return 80 // internal_error
	}
	return 42 // bad_certificate
}
