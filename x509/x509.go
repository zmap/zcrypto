// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	// all of the hash libraries need to be imported for side-effects,
	// so that crypto.RegisterHash is called
	_ "crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"

	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/zmap/zcrypto/ct"
	"github.com/zmap/zcrypto/x509/pkix"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if _, err = asn1.Unmarshal(derBytes, &pki); err != nil {
		return
	}
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}
	return parsePublicKey(algo, &pki)
}

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is technically
		// superfluous, but most other code includes it and, by
		// doing this, we match their public key hashes.
		publicKeyAlgorithm.Parameters = asn1.RawValue{
			Tag: 5,
		}
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case *AugmentedECDSA:
		return marshalPublicKey(pub.Pub)
	default:
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: only RSA and ECDSA public keys supported")
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// MarshalPKIXPublicKey serialises a public key to DER-encoded PKIX format.
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type AugmentedECDSA struct {
	Pub *ecdsa.PublicKey
	Raw asn1.BitString
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

type SignatureAlgorithm int
type SignatureAlgorithmOID asn1.ObjectIdentifier

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	total_signature_algorithms
)

var signatureAlgorithmNames = []string{
	"unknown_algorithm",
	"MD2WithRSA",
	"MD5WithRSA",
	"SHA1WithRSA",
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"DSAWithSHA1",
	"DSAWithSHA256",
	"ECDSAWithSHA1",
	"ECDSAWithSHA256",
	"ECDSAWitHSHA384",
	"ECDSAWithSHA512",
}

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	ECDSA
	total_key_algorithms
)

var keyAlgorithmNames = []string{
	"unknown_algorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

// OIDs for signature algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
// md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
// md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
// sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
// dsaWithSha1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
// ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
// 	  iso(1) member-body(2) us(840) ansi-x962(10045)
//    signatures(4) ecdsa-with-SHA1(1)}
//
//
// RFC 4055 5 PKCS #1 Version 1.5
//
// sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
// sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
//
// RFC 5758 3.1 DSA Signature Algorithms
//
// dsaWithSha256 OBJECT IDENTIFIER ::= {
//    joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//    csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var signatureAlgorithmDetails = []struct {
	algo       SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{MD2WithRSA, oidSignatureMD2WithRSA, RSA, crypto.Hash(0) /* no value for MD2 */},
	{MD5WithRSA, oidSignatureMD5WithRSA, RSA, crypto.MD5},
	{SHA1WithRSA, oidSignatureSHA1WithRSA, RSA, crypto.SHA1},
	{SHA256WithRSA, oidSignatureSHA256WithRSA, RSA, crypto.SHA256},
	{SHA384WithRSA, oidSignatureSHA384WithRSA, RSA, crypto.SHA384},
	{SHA512WithRSA, oidSignatureSHA512WithRSA, RSA, crypto.SHA512},
	{DSAWithSHA1, oidSignatureDSAWithSHA1, DSA, crypto.SHA1},
	{DSAWithSHA256, oidSignatureDSAWithSHA256, DSA, crypto.SHA256},
	{ECDSAWithSHA1, oidSignatureECDSAWithSHA1, ECDSA, crypto.SHA1},
	{ECDSAWithSHA256, oidSignatureECDSAWithSHA256, ECDSA, crypto.SHA256},
	{ECDSAWithSHA384, oidSignatureECDSAWithSHA384, ECDSA, crypto.SHA384},
	{ECDSAWithSHA512, oidSignatureECDSAWithSHA512, ECDSA, crypto.SHA512},
}

func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return UnknownSignatureAlgorithm
}

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return RSA
	case oid.Equal(oidPublicKeyDSA):
		return DSA
	case oid.Equal(oidPublicKeyECDSA):
		return ECDSA
	}
	return UnknownPublicKeyAlgorithm
}

func getMaxCertValidationLevel(oids []asn1.ObjectIdentifier) CertValidationLevel {
	maxOID := DV
	for _, oid := range oids {
		if _, ok := ExtendedValidationOIDs[oid.String()]; ok {
			return EV
		} else if _, ok := OrganizationValidationOIDs[oid.String()]; ok {
			maxOID = OV
		}
	}

	return maxOID
}

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

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

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }

// OIDS are generated by extended_key_usage_gen.go

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var nativeExtKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIpsecEndSystem, oidExtKeyUsageIpsecEndSystem},
	{ExtKeyUsageIpsecTunnel, oidExtKeyUsageIpsecTunnel},
	{ExtKeyUsageIpsecUser, oidExtKeyUsageIpsecUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOcspSigning, oidExtKeyUsageOcspSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	s := oid.String()
	eku, ok = ekuConstants[s]
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range nativeExtKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm
	SelfSigned         bool

	SignatureAlgorithmOID asn1.ObjectIdentifier

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	PublicKeyAlgorithmOID asn1.ObjectIdentifier

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	ValidityPeriod      int
	KeyUsage            KeyUsage

	IssuerUniqueId  asn1.BitString
	SubjectUniqueId asn1.BitString

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	BasicConstraintsValid bool // if true then the next two fields are valid.
	IsCA                  bool
	MaxPathLen            int
	// MaxPathLenZero indicates that BasicConstraintsValid==true and
	// MaxPathLen==0 should be interpreted as an actual Max path length
	// of zero. Otherwise, that combination is interpreted as MaxPathLen
	// not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values
	OtherNames     []pkix.OtherName
	DNSNames       []string
	EmailAddresses []string
	DirectoryNames []pkix.Name
	EDIPartyNames  []pkix.EDIPartyName
	URIs           []string
	IPAddresses    []net.IP
	RegisteredIDs  []asn1.ObjectIdentifier

	// Issuer Alternative Name values
	IANOtherNames     []pkix.OtherName
	IANDNSNames       []string
	IANEmailAddresses []string
	IANDirectoryNames []pkix.Name
	IANEDIPartyNames  []pkix.EDIPartyName
	IANURIs           []string
	IANIPAddresses    []net.IP
	IANRegisteredIDs  []asn1.ObjectIdentifier

	// Certificate Policies values
	QualifierId          [][]asn1.ObjectIdentifier
	CPSuri               [][]string
	ExplicitTexts        [][]asn1.RawValue
	NoticeRefOrgnization [][]asn1.RawValue
	NoticeRefNumbers     [][]NoticeNumber

	ParsedExplicitTexts         [][]string
	ParsedNoticeRefOrganization [][]string

	// Name constraints
	NameConstraintsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSNames       []GeneralSubtreeString
	ExcludedDNSNames        []GeneralSubtreeString
	PermittedEmailAddresses []GeneralSubtreeString
	ExcludedEmailAddresses  []GeneralSubtreeString
	PermittedIPAddresses    []GeneralSubtreeIP
	ExcludedIPAddresses     []GeneralSubtreeIP
	PermittedDirectoryNames []GeneralSubtreeName
	ExcludedDirectoryNames  []GeneralSubtreeName
	PermittedEdiPartyNames  []GeneralSubtreeEdi
	ExcludedEdiPartyNames   []GeneralSubtreeEdi
	PermittedRegisteredIDs  []GeneralSubtreeOid
	ExcludedRegisteredIDs   []GeneralSubtreeOid
	PermittedX400Addresses  []GeneralSubtreeRaw
	ExcludedX400Addresses   []GeneralSubtreeRaw

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
	ValidationLevel   CertValidationLevel

	// Fingerprints
	FingerprintMD5    CertificateFingerprint
	FingerprintSHA1   CertificateFingerprint
	FingerprintSHA256 CertificateFingerprint
	FingerprintNoCT   CertificateFingerprint

	// SPKI
	SPKIFingerprint           CertificateFingerprint
	SPKISubjectFingerprint    CertificateFingerprint
	TBSCertificateFingerprint CertificateFingerprint

	IsPrecert bool

	// Internal
	validSignature bool

	// CT
	SignedCertificateTimestampList []*ct.SignedCertificateTimestamp
}

type NoticeNumber []int

type GeneralSubtreeString struct {
	Data string
	Max  int
	Min  int
}

type GeneralSubtreeIP struct {
	Data net.IPNet
	Max  int
	Min  int
}

type GeneralSubtreeName struct {
	Data pkix.Name
	Max  int
	Min  int
}

type GeneralSubtreeEdi struct {
	Data pkix.EDIPartyName
	Max  int
	Min  int
}

type GeneralSubtreeOid struct {
	Data asn1.ObjectIdentifier
	Max  int
	Min  int
}

type GeneralSubtreeRaw struct {
	Data asn1.RawValue
	Max  int
	Min  int
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

// Equal returns true if the two certificates have byte-equal Raw values.
func (c *Certificate) Equal(other *Certificate) bool {
	return bytes.Equal(c.Raw, other.Raw)
}

// Entrust have a broken root certificate (CN=Entrust.net Certification
// Authority (2048)) which isn't marked as a CA certificate and is thus invalid
// according to PKIX.
// We recognise this certificate by its SubjectPublicKeyInfo and exempt it
// from the Basic Constraints requirement.
// See http://www.entrust.net/knowledge-base/technote.cfm?tn=7869
//
// TODO(agl): remove this hack once their reissued root is sufficiently
// widespread.
var entrustBrokenSPKI = []byte{
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0x97, 0xa3, 0x2d, 0x3c, 0x9e, 0xde, 0x05,
	0xda, 0x13, 0xc2, 0x11, 0x8d, 0x9d, 0x8e, 0xe3,
	0x7f, 0xc7, 0x4b, 0x7e, 0x5a, 0x9f, 0xb3, 0xff,
	0x62, 0xab, 0x73, 0xc8, 0x28, 0x6b, 0xba, 0x10,
	0x64, 0x82, 0x87, 0x13, 0xcd, 0x57, 0x18, 0xff,
	0x28, 0xce, 0xc0, 0xe6, 0x0e, 0x06, 0x91, 0x50,
	0x29, 0x83, 0xd1, 0xf2, 0xc3, 0x2a, 0xdb, 0xd8,
	0xdb, 0x4e, 0x04, 0xcc, 0x00, 0xeb, 0x8b, 0xb6,
	0x96, 0xdc, 0xbc, 0xaa, 0xfa, 0x52, 0x77, 0x04,
	0xc1, 0xdb, 0x19, 0xe4, 0xae, 0x9c, 0xfd, 0x3c,
	0x8b, 0x03, 0xef, 0x4d, 0xbc, 0x1a, 0x03, 0x65,
	0xf9, 0xc1, 0xb1, 0x3f, 0x72, 0x86, 0xf2, 0x38,
	0xaa, 0x19, 0xae, 0x10, 0x88, 0x78, 0x28, 0xda,
	0x75, 0xc3, 0x3d, 0x02, 0x82, 0x02, 0x9c, 0xb9,
	0xc1, 0x65, 0x77, 0x76, 0x24, 0x4c, 0x98, 0xf7,
	0x6d, 0x31, 0x38, 0xfb, 0xdb, 0xfe, 0xdb, 0x37,
	0x02, 0x76, 0xa1, 0x18, 0x97, 0xa6, 0xcc, 0xde,
	0x20, 0x09, 0x49, 0x36, 0x24, 0x69, 0x42, 0xf6,
	0xe4, 0x37, 0x62, 0xf1, 0x59, 0x6d, 0xa9, 0x3c,
	0xed, 0x34, 0x9c, 0xa3, 0x8e, 0xdb, 0xdc, 0x3a,
	0xd7, 0xf7, 0x0a, 0x6f, 0xef, 0x2e, 0xd8, 0xd5,
	0x93, 0x5a, 0x7a, 0xed, 0x08, 0x49, 0x68, 0xe2,
	0x41, 0xe3, 0x5a, 0x90, 0xc1, 0x86, 0x55, 0xfc,
	0x51, 0x43, 0x9d, 0xe0, 0xb2, 0xc4, 0x67, 0xb4,
	0xcb, 0x32, 0x31, 0x25, 0xf0, 0x54, 0x9f, 0x4b,
	0xd1, 0x6f, 0xdb, 0xd4, 0xdd, 0xfc, 0xaf, 0x5e,
	0x6c, 0x78, 0x90, 0x95, 0xde, 0xca, 0x3a, 0x48,
	0xb9, 0x79, 0x3c, 0x9b, 0x19, 0xd6, 0x75, 0x05,
	0xa0, 0xf9, 0x88, 0xd7, 0xc1, 0xe8, 0xa5, 0x09,
	0xe4, 0x1a, 0x15, 0xdc, 0x87, 0x23, 0xaa, 0xb2,
	0x75, 0x8c, 0x63, 0x25, 0x87, 0xd8, 0xf8, 0x3d,
	0xa6, 0xc2, 0xcc, 0x66, 0xff, 0xa5, 0x66, 0x68,
	0x55, 0x02, 0x03, 0x01, 0x00, 0x01,
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) (err error) {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	// (except for Entrust, see comment above entrustBrokenSPKI)
	if (parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA) &&
		!bytes.Equal(c.RawSubjectPublicKeyInfo, entrustBrokenSPKI) {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	if parent.Subject.String() != c.Issuer.String() {
		return errors.New("Mis-match issuer/subject")
	}

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) (err error) {
	var hashType crypto.Hash

	switch algo {
	case SHA1WithRSA, DSAWithSHA1, ECDSAWithSHA1:
		hashType = crypto.SHA1
	case SHA256WithRSA, DSAWithSHA256, ECDSAWithSHA256:
		hashType = crypto.SHA256
	case SHA384WithRSA, ECDSAWithSHA384:
		hashType = crypto.SHA384
	case SHA512WithRSA, ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
	case *dsa.PublicKey:
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(signature, dsaSig); err != nil {
			return err
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return errors.New("x509: DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
			return errors.New("x509: DSA verification failure")
		}
		return
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	case *AugmentedECDSA:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub.Pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

// CheckCRLSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) (err error) {
	algo := getSignatureAlgorithmFromOID(crl.SignatureAlgorithm.Algorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifierInfo `asn1:"optional"`
}

type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

type userNotice struct {
	NoticeRef    noticeReference `asn1:"optional"`
	ExplicitText asn1.RawValue   `asn1:"optional"`
}

type noticeReference struct {
	Organization  asn1.RawValue
	NoticeNumbers []int
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Value asn1.RawValue `asn1:"optional"`
	Min   int           `asn1:"tag:0,default:0,optional"`
	Max   int           `asn1:"tag:1,optional"`
}

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     asn1.RawValue    `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case RSA:
		p := new(rsaPublicKey)
		_, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case DSA:
		var p *big.Int
		_, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		paramsData := keyData.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		_, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	case ECDSA:
		paramsData := keyData.Algorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		_, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, err
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		key := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}

		pub := &AugmentedECDSA{
			Pub: key,
			Raw: keyData.PublicKey,
		}
		return pub, nil
	default:
		return nil, nil
	}
}

func parseGeneralNames(value []byte) (otherNames []pkix.OtherName, dnsNames, emailAddresses, URIs []string, directoryNames []pkix.Name, ediPartyNames []pkix.EDIPartyName, ipAddresses []net.IP, registeredIDs []asn1.ObjectIdentifier, err error) {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	if _, err = asn1.Unmarshal(value, &seq); err != nil {
		return
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}
		switch v.Tag {
		case 0:
			var oName pkix.OtherName
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &oName, "tag:0")
			if err != nil {
				return
			}
			otherNames = append(otherNames, oName)
		case 1:
			emailAddresses = append(emailAddresses, string(v.Bytes))
		case 2:
			dnsNames = append(dnsNames, string(v.Bytes))
		case 4:
			var rdn pkix.RDNSequence
			_, err = asn1.Unmarshal(v.Bytes, &rdn)
			if err != nil {
				return
			}
			var dir pkix.Name
			dir.FillFromRDNSequence(&rdn)
			directoryNames = append(directoryNames, dir)
		case 5:
			var ediName pkix.EDIPartyName
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &ediName, "tag:5")
			if err != nil {
				return
			}
			ediPartyNames = append(ediPartyNames, ediName)
		case 6:
			URIs = append(URIs, string(v.Bytes))
		case 7:
			switch len(v.Bytes) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, v.Bytes)
			default:
				err = errors.New("x509: certificate contained IP address of length " + strconv.Itoa(len(v.Bytes)))
				return
			}
		case 8:
			var id asn1.ObjectIdentifier
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &id, "tag:8")
			if err != nil {
				return
			}
			registeredIDs = append(registeredIDs, id)
		}
	}

	return
}

func parseCertificate(in *certificate) (*Certificate, error) {
	out := new(Certificate)
	out.Raw = in.Raw
	out.RawTBSCertificate = in.TBSCertificate.Raw
	out.RawSubjectPublicKeyInfo = in.TBSCertificate.PublicKey.Raw
	out.RawSubject = in.TBSCertificate.Subject.FullBytes
	out.RawIssuer = in.TBSCertificate.Issuer.FullBytes

	// Fingerprints
	out.FingerprintMD5 = MD5Fingerprint(in.Raw)
	out.FingerprintSHA1 = SHA1Fingerprint(in.Raw)
	out.FingerprintSHA256 = SHA256Fingerprint(in.Raw)
	out.SPKIFingerprint = SHA256Fingerprint(in.TBSCertificate.PublicKey.Raw)
	out.TBSCertificateFingerprint = SHA256Fingerprint(in.TBSCertificate.Raw)

	tbs := in.TBSCertificate
	extensions := in.TBSCertificate.Extensions

	// Blow away the raw data since it also includes CT data
	tbs.Raw = nil

	// remove the CT extensions
	flag := false
	for i, extension := range in.TBSCertificate.Extensions {
		if extension.Id.Equal(oidExtensionCTPrecertificatePoison) == true {
			extensions = append(extensions[:i], extensions[i+1:]...)
			if flag {
				break
			}
			flag = true
		}
		if extension.Id.Equal(oidExtensionSignedCertificateTimestampList) {
			extensions = append(extensions[:i], extensions[i+1:]...)
			if flag {
				break
			}
			flag = true
		}
	}

	tbs.Extensions = extensions

	tbsbytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	if tbsbytes == nil {
		return nil, asn1.SyntaxError{Msg: "Trailing data"}
	}
	out.FingerprintNoCT = SHA256Fingerprint(tbsbytes[:])

	// Hash both SPKI and Subject to create a fingerprint that we can use to describe a CA
	hasher := sha256.New()
	hasher.Write(in.TBSCertificate.PublicKey.Raw)
	hasher.Write(in.TBSCertificate.Subject.FullBytes)
	out.SPKISubjectFingerprint = hasher.Sum(nil)

	out.Signature = in.SignatureValue.RightAlign()
	out.SignatureAlgorithm =
		getSignatureAlgorithmFromOID(in.TBSCertificate.SignatureAlgorithm.Algorithm)

	out.SignatureAlgorithmOID = in.TBSCertificate.SignatureAlgorithm.Algorithm

	out.PublicKeyAlgorithm =
		getPublicKeyAlgorithmFromOID(in.TBSCertificate.PublicKey.Algorithm.Algorithm)
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCertificate.PublicKey)
	if err != nil {
		return nil, err
	}

	out.PublicKeyAlgorithmOID = in.TBSCertificate.PublicKey.Algorithm.Algorithm
	out.Version = in.TBSCertificate.Version + 1
	out.SerialNumber = in.TBSCertificate.SerialNumber

	var issuer, subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(in.TBSCertificate.Subject.FullBytes, &subject); err != nil {
		//log.Print("Err parsing asn1 of TBSCertificate %s", in.TBSCertificate.Subject)
		return nil, err
	}
	if _, err := asn1.Unmarshal(in.TBSCertificate.Issuer.FullBytes, &issuer); err != nil {
		return nil, err
	}

	out.Issuer.FillFromRDNSequence(&issuer)
	out.Subject.FillFromRDNSequence(&subject)

	// Check if self-signed
	if bytes.Equal(out.RawSubject, out.RawIssuer) {
		// Possibly self-signed, check the signature against itself.
		if out.CheckSignature(out.SignatureAlgorithm, out.RawTBSCertificate, out.Signature) == nil {
			out.SelfSigned = true
		}
	}

	out.NotBefore = in.TBSCertificate.Validity.NotBefore
	out.NotAfter = in.TBSCertificate.Validity.NotAfter

	out.ValidityPeriod = int(out.NotAfter.Sub(out.NotBefore).Seconds())

	out.IssuerUniqueId = in.TBSCertificate.UniqueId
	out.SubjectUniqueId = in.TBSCertificate.SubjectUniqueId

	for _, e := range in.TBSCertificate.Extensions {
		out.Extensions = append(out.Extensions, e)

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				// RFC 5280, 4.2.1.3
				var usageBits asn1.BitString
				_, err := asn1.Unmarshal(e.Value, &usageBits)

				if err == nil {
					var usage int
					for i := 0; i < 9; i++ {
						if usageBits.At(i) != 0 {
							usage |= 1 << uint(i)
						}
					}
					out.KeyUsage = KeyUsage(usage)
					continue
				}
			case 19:
				// RFC 5280, 4.2.1.9
				var constraints basicConstraints
				_, err := asn1.Unmarshal(e.Value, &constraints)

				if err == nil {
					out.BasicConstraintsValid = true
					out.IsCA = constraints.IsCA
					out.MaxPathLen = constraints.MaxPathLen
					out.MaxPathLenZero = out.MaxPathLen == 0
					continue
				}
			case 17:
				out.OtherNames, out.DNSNames, out.EmailAddresses, out.URIs, out.DirectoryNames, out.EDIPartyNames, out.IPAddresses, out.RegisteredIDs, err = parseGeneralNames(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.DNSNames) > 0 || len(out.EmailAddresses) > 0 || len(out.IPAddresses) > 0 {
					continue
				}
				// If we didn't parse any of the names then we
				// fall through to the critical check below.
			case 18:
				out.IANOtherNames, out.IANDNSNames, out.IANEmailAddresses, out.IANURIs, out.IANDirectoryNames, out.IANEDIPartyNames, out.IANIPAddresses, out.IANRegisteredIDs, err = parseGeneralNames(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.IANDNSNames) > 0 || len(out.IANEmailAddresses) > 0 || len(out.IANIPAddresses) > 0 {
					continue
				}
			case 30:
				// RFC 5280, 4.2.1.10

				// NameConstraints ::= SEQUENCE {
				//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
				//
				// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
				//
				// GeneralSubtree ::= SEQUENCE {
				//      base                    GeneralName,
				//      Min         [0]     BaseDistance DEFAULT 0,
				//      Max         [1]     BaseDistance OPTIONAL }
				//
				// BaseDistance ::= INTEGER (0..MAX)

				var constraints nameConstraints
				_, err := asn1.Unmarshal(e.Value, &constraints)
				if err != nil {
					return nil, err
				}

				if e.Critical {
					out.NameConstraintsCritical = true
				}

				for _, subtree := range constraints.Permitted {
					switch subtree.Value.Tag {
					case 1:
						out.PermittedEmailAddresses = append(out.PermittedEmailAddresses, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 2:
						out.PermittedDNSNames = append(out.PermittedDNSNames, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 3:
						out.PermittedX400Addresses = append(out.PermittedX400Addresses, GeneralSubtreeRaw{Data: subtree.Value, Max: subtree.Max, Min: subtree.Min})
					case 4:
						var rawdn pkix.RDNSequence
						if _, err := asn1.Unmarshal(subtree.Value.Bytes, &rawdn); err != nil {
							return out, err
						}
						var dn pkix.Name
						dn.FillFromRDNSequence(&rawdn)
						out.PermittedDirectoryNames = append(out.PermittedDirectoryNames, GeneralSubtreeName{Data: dn, Max: subtree.Max, Min: subtree.Min})
					case 5:
						var ediName pkix.EDIPartyName
						_, err = asn1.UnmarshalWithParams(subtree.Value.FullBytes, &ediName, "tag:5")
						if err != nil {
							return out, err
						}
						out.PermittedEdiPartyNames = append(out.PermittedEdiPartyNames, GeneralSubtreeEdi{Data: ediName, Max: subtree.Max, Min: subtree.Min})
					case 7:
						switch len(subtree.Value.Bytes) {
						case net.IPv4len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv4len], Mask: subtree.Value.Bytes[net.IPv4len:]}
							out.PermittedIPAddresses = append(out.PermittedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						case net.IPv6len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv6len], Mask: subtree.Value.Bytes[net.IPv6len:]}
							out.PermittedIPAddresses = append(out.PermittedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						default:
							return out, errors.New("x509: certificate name constraint contained IP address range of length " + strconv.Itoa(len(subtree.Value.Bytes)))
						}
					case 8:
						var id asn1.ObjectIdentifier
						_, err = asn1.UnmarshalWithParams(subtree.Value.FullBytes, &id, "tag:8")
						if err != nil {
							return out, err
						}
						out.PermittedRegisteredIDs = append(out.PermittedRegisteredIDs, GeneralSubtreeOid{Data: id, Max: subtree.Max, Min: subtree.Min})
					}
				}
				for _, subtree := range constraints.Excluded {
					switch subtree.Value.Tag {
					case 1:
						out.ExcludedEmailAddresses = append(out.ExcludedEmailAddresses, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 2:
						out.ExcludedDNSNames = append(out.ExcludedDNSNames, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 3:
						out.ExcludedX400Addresses = append(out.ExcludedX400Addresses, GeneralSubtreeRaw{Data: subtree.Value, Max: subtree.Max, Min: subtree.Min})
					case 4:
						var rawdn pkix.RDNSequence
						if _, err := asn1.Unmarshal(subtree.Value.Bytes, &rawdn); err != nil {
							return out, err
						}
						var dn pkix.Name
						dn.FillFromRDNSequence(&rawdn)
						out.ExcludedDirectoryNames = append(out.ExcludedDirectoryNames, GeneralSubtreeName{Data: dn, Max: subtree.Max, Min: subtree.Min})
					case 5:
						var ediName pkix.EDIPartyName
						_, err = asn1.Unmarshal(subtree.Value.Bytes, &ediName)
						if err != nil {
							return out, err
						}
						out.ExcludedEdiPartyNames = append(out.ExcludedEdiPartyNames, GeneralSubtreeEdi{Data: ediName, Max: subtree.Max, Min: subtree.Min})
					case 7:
						switch len(subtree.Value.Bytes) {
						case net.IPv4len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv4len], Mask: subtree.Value.Bytes[net.IPv4len:]}
							out.ExcludedIPAddresses = append(out.ExcludedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						case net.IPv6len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv6len], Mask: subtree.Value.Bytes[net.IPv6len:]}
							out.ExcludedIPAddresses = append(out.ExcludedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						default:
							return out, errors.New("x509: certificate name constraint contained IP address range of length " + strconv.Itoa(len(subtree.Value.Bytes)))
						}
					case 8:
						var id asn1.ObjectIdentifier
						_, err = asn1.Unmarshal(subtree.Value.Bytes, &id)
						if err != nil {
							return out, err
						}
						out.ExcludedRegisteredIDs = append(out.ExcludedRegisteredIDs, GeneralSubtreeOid{Data: id, Max: subtree.Max, Min: subtree.Min})
					}
				}
				continue

			case 31:
				// RFC 5280, 4.2.1.14

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

				var cdp []distributionPoint
				_, err := asn1.Unmarshal(e.Value, &cdp)
				if err != nil {
					return nil, err
				}

				for _, dp := range cdp {
					// Per RFC 5280, 4.2.1.13, one of distributionPoint or cRLIssuer may be empty.
					if len(dp.DistributionPoint.FullName.Bytes) == 0 {
						continue
					}

					var n asn1.RawValue
					_, err = asn1.Unmarshal(dp.DistributionPoint.FullName.Bytes, &n)
					if err != nil {
						return nil, err
					}

					if n.Tag == 6 {
						out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(n.Bytes))
					}
				}
				continue

			case 35:
				// RFC 5280, 4.2.1.1
				var a authKeyId
				_, err = asn1.Unmarshal(e.Value, &a)
				if err != nil {
					return nil, err
				}
				out.AuthorityKeyId = a.Id
				continue

			case 37:
				// RFC 5280, 4.2.1.12.  Extended Key Usage

				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER

				var keyUsage []asn1.ObjectIdentifier
				_, err = asn1.Unmarshal(e.Value, &keyUsage)
				if err != nil {
					return nil, err
				}

				for _, u := range keyUsage {
					if extKeyUsage, ok := extKeyUsageFromOID(u); ok {
						out.ExtKeyUsage = append(out.ExtKeyUsage, extKeyUsage)
					} else {
						out.UnknownExtKeyUsage = append(out.UnknownExtKeyUsage, u)
					}
				}

				continue

			case 14:
				// RFC 5280, 4.2.1.2
				var keyid []byte
				_, err = asn1.Unmarshal(e.Value, &keyid)
				if err != nil {
					return nil, err
				}
				out.SubjectKeyId = keyid
				continue

			case 32:
				// RFC 5280 4.2.1.4: Certificate Policies
				var policies []policyInformation
				if _, err = asn1.Unmarshal(e.Value, &policies); err != nil {
					return nil, err
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, len(policies))
				out.QualifierId = make([][]asn1.ObjectIdentifier, len(policies))
				out.ExplicitTexts = make([][]asn1.RawValue, len(policies))
				out.NoticeRefOrgnization = make([][]asn1.RawValue, len(policies))
				out.NoticeRefNumbers = make([][]NoticeNumber, len(policies))
				out.ParsedExplicitTexts = make([][]string, len(policies))
				out.ParsedNoticeRefOrganization = make([][]string, len(policies))
				out.CPSuri = make([][]string, len(policies))

				for i, policy := range policies {
					out.PolicyIdentifiers[i] = policy.Policy
					// parse optional Qualifier for zlint
					for _, qualifier := range policy.Qualifiers {
						out.QualifierId[i] = append(out.QualifierId[i], qualifier.PolicyQualifierId)
						userNoticeOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
						cpsURIOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
						if qualifier.PolicyQualifierId.Equal(userNoticeOID) {
							var un userNotice
							if _, err = asn1.Unmarshal(qualifier.Qualifier.FullBytes, &un); err != nil {
								return nil, err
							}
							if len(un.ExplicitText.Bytes) != 0 {
								out.ExplicitTexts[i] = append(out.ExplicitTexts[i], un.ExplicitText)
								out.ParsedExplicitTexts[i] = append(out.ParsedExplicitTexts[i], string(un.ExplicitText.Bytes))
							}
							if un.NoticeRef.Organization.Bytes != nil || un.NoticeRef.NoticeNumbers != nil {
								out.NoticeRefOrgnization[i] = append(out.NoticeRefOrgnization[i], un.NoticeRef.Organization)
								out.NoticeRefNumbers[i] = append(out.NoticeRefNumbers[i], un.NoticeRef.NoticeNumbers)
								out.ParsedNoticeRefOrganization[i] = append(out.ParsedNoticeRefOrganization[i], string(un.NoticeRef.Organization.Bytes))
							}
						}
						if qualifier.PolicyQualifierId.Equal(cpsURIOID) {
							var cpsURIRaw asn1.RawValue
							if _, err = asn1.Unmarshal(qualifier.Qualifier.FullBytes, &cpsURIRaw); err != nil {
								return nil, err
							}
							out.CPSuri[i] = append(out.CPSuri[i], string(cpsURIRaw.Bytes))
						}
					}
				}
				out.ValidationLevel = getMaxCertValidationLevel(out.PolicyIdentifiers)
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			var aia []authorityInfoAccess
			if _, err = asn1.Unmarshal(e.Value, &aia); err != nil {
				return nil, err
			}

			for _, v := range aia {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if v.Location.Tag != 6 {
					continue
				}
				if v.Method.Equal(oidAuthorityInfoAccessOcsp) {
					out.OCSPServer = append(out.OCSPServer, string(v.Location.Bytes))
				} else if v.Method.Equal(oidAuthorityInfoAccessIssuers) {
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(v.Location.Bytes))
				}
			}
		} else if e.Id.Equal(oidExtensionSignedCertificateTimestampList) {
			// SignedCertificateTimestamp
			//var scts asn1.RawValue
			var scts []byte
			if _, err = asn1.Unmarshal(e.Value, &scts); err != nil {
				return nil, err
			}
			// ignore length of
			if len(scts) < 2 {
				return nil, errors.New("malformed SCT extension: length field")
			}
			scts = scts[2:]
			for len(scts) > 0 {
				length := int(scts[1]) + (int(scts[0]) << 8)
				if (length + 2) > len(scts) {
					return nil, errors.New("malformed SCT extension: incomplete SCT")
				}
				sct, err := ct.DeserializeSCT(bytes.NewReader(scts[2 : length+2]))
				if err != nil {
					return nil, err
				}
				scts = scts[2+length:]
				out.SignedCertificateTimestampList = append(out.SignedCertificateTimestampList, sct)
			}
		} else if e.Id.Equal(oidExtensionCTPrecertificatePoison) {
			if e.Value[0] == 5 && e.Value[1] == 0 {
				out.IsPrecert = true
				continue
			} else {
				return nil, UnhandledCriticalExtension{e.Id, "Malformed precert poison"}
			}
		}
		//if e.Critical {
		//	return out, UnhandledCriticalExtension{e.Id}
		//}
	}
	return out, nil
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	var cert certificate
	rest, err := asn1.Unmarshal(asn1Data, &cert)
	if err != nil {
		//log.Print("Err unmarshalling asn1Data", asn1Data, rest)
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificate(&cert)
}

func ParseTBSCertificate(asn1Data []byte) (*Certificate, error) {
	var tbsCert tbsCertificate
	rest, err := asn1.Unmarshal(asn1Data, &tbsCert)
	if err != nil {
		//log.Print("Err unmarshalling asn1Data", asn1Data, rest)
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	return parseCertificate(&certificate{
		Raw:            tbsCert.Raw,
		TBSCertificate: tbsCert})
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER
// data. The certificates must be concatenated with no intermediate padding.
func ParseCertificates(asn1Data []byte) ([]*Certificate, error) {
	var v []*certificate

	for len(asn1Data) > 0 {
		cert := new(certificate)
		var err error
		asn1Data, err = asn1.Unmarshal(asn1Data, cert)
		if err != nil {
			return nil, err
		}
		v = append(v, cert)
	}

	ret := make([]*Certificate, len(v))
	for i, ci := range v {
		cert, err := parseCertificate(ci)
		if err != nil {
			return nil, err
		}
		ret[i] = cert
	}

	return ret, nil
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

var (
	oidExtensionSubjectKeyId                   = []int{2, 5, 29, 14}
	oidExtensionKeyUsage                       = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage               = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId                 = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints               = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName                 = []int{2, 5, 29, 17}
	oidExtensionIssuerAltName                  = []int{2, 5, 29, 18}
	oidExtensionCertificatePolicies            = []int{2, 5, 29, 32}
	oidExtensionNameConstraints                = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints          = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess            = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionSignedCertificateTimestampList = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidNotInExtensions returns whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	return asn1.Marshal(rawValues)
}

func buildExtensions(template *Certificate) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* Max number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionKeyUsage
		ret[n].Critical = true

		var a [2]byte
		a[0] = reverseBitsInAByte(byte(template.KeyUsage))
		a[1] = reverseBitsInAByte(byte(template.KeyUsage >> 8))

		l := 1
		if a[1] != 0 {
			l = 2
		}

		ret[n].Value, err = asn1.Marshal(asn1.BitString{Bytes: a[0:l], BitLength: l * 8})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionExtendedKeyUsage

		var oids []asn1.ObjectIdentifier
		for _, u := range template.ExtKeyUsage {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				panic("internal error")
			}
		}

		oids = append(oids, template.UnknownExtKeyUsage...)

		ret[n].Value, err = asn1.Marshal(oids)
		if err != nil {
			return
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		// Leaving MaxPathLen as zero indicates that no Max path
		// length is desired, unless MaxPathLenZero is set. A value of
		// -1 causes encoding/asn1 to omit the value as desired.
		maxPathLen := template.MaxPathLen
		if maxPathLen == 0 && !template.MaxPathLenZero {
			maxPathLen = -1
		}
		ret[n].Id = oidExtensionBasicConstraints
		ret[n].Value, err = asn1.Marshal(basicConstraints{template.IsCA, maxPathLen})
		ret[n].Critical = true
		if err != nil {
			return
		}
		n++
	}

	if len(template.SubjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(template.SubjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(template.AuthorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{template.AuthorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCertificatePolicies
		policies := make([]policyInformation, len(template.PolicyIdentifiers))
		for i, policy := range template.PolicyIdentifiers {
			policies[i].Policy = policy
		}
		ret[n].Value, err = asn1.Marshal(policies)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.PermittedEmailAddresses) > 0 || len(template.PermittedDNSNames) > 0 || len(template.PermittedDirectoryNames) > 0 ||
		len(template.PermittedIPAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 || len(template.ExcludedDNSNames) > 0 ||
		len(template.ExcludedDirectoryNames) > 0 || len(template.ExcludedIPAddresses) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		if template.NameConstraintsCritical {
			ret[n].Critical = true
		}

		var out nameConstraints

		for _, permitted := range template.PermittedEmailAddresses {
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(permitted.Data)}})
		}
		for _, excluded := range template.ExcludedEmailAddresses {
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(excluded.Data)}})
		}
		for _, permitted := range template.PermittedDNSNames {
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(permitted.Data)}})
		}
		for _, excluded := range template.ExcludedDNSNames {
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(excluded.Data)}})
		}
		for _, permitted := range template.PermittedDirectoryNames {
			var dn []byte
			dn, err = asn1.Marshal(permitted.Data.ToRDNSequence())
			if err != nil {
				return
			}
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: dn}})
		}
		for _, excluded := range template.ExcludedDirectoryNames {
			var dn []byte
			dn, err = asn1.Marshal(excluded.Data.ToRDNSequence())
			if err != nil {
				return
			}
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: dn}})
		}
		for _, permitted := range template.PermittedIPAddresses {
			ip := append(permitted.Data.IP, permitted.Data.Mask...)
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 7, Class: 2, Bytes: ip}})
		}
		for _, excluded := range template.ExcludedIPAddresses {
			ip := append(excluded.Data.IP, excluded.Data.Mask...)
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 7, Class: 2, Bytes: ip}})
		}
		ret[n].Value, err = asn1.Marshal(out)
		if err != nil {
			return
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			rawFullName, _ := asn1.Marshal(asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)})

			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: rawFullName},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the Max number
	// of elements in the make() at the top of the function.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPrivateKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPrivateKey(priv interface{}, requestedSigAlgo SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType PublicKeyAlgorithm

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		pubType = RSA
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		hashFunc = crypto.SHA256

	case *ecdsa.PrivateKey:
		pubType = ECDSA

		switch priv.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	default:
		err = errors.New("x509: only RSA and ECDSA private keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// CreateCertificate creates a new certificate based on a template. The
// following members of template are used: SerialNumber, Subject, NotBefore,
// NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid,
// IsCA, MaxPathLen, SubjectKeyId, DNSNames, NameConstraintsCritical,
// PermittedDNSNames, ExcludedDNSNames, PermittedEmailAddresses,
// ExcludedEmailAddresses, PermittedIPAddresses, ExcludedIPAddresses,
// PermittedDirectoryNames, ExcludedDirectoryNames, SignatureAlgorithm.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The only supported key types are RSA and ECDSA (*rsa.PublicKey or
// *ecdsa.PublicKey for pub, *rsa.PrivateKey or *ecdsa.PrivateKey for priv).
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub interface{}, priv interface{}) (cert []byte, err error) {
	hashFunc, signatureAlgorithm, err := signingParamsForPrivateKey(priv, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return
	}

	if len(parent.SubjectKeyId) > 0 {
		template.AuthorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template)
	if err != nil {
		return
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return
	}

	c.Raw = tbsCertContents

	h := hashFunc.New()
	h.Write(tbsCertContents)
	digest := h.Sum(nil)

	var signature []byte

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand, priv, hashFunc, digest)
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand, priv, digest); err == nil {
			signature, err = asn1.Marshal(ecdsaSignature{r, s})
		}
	default:
		panic("internal error")
	}

	if err != nil {
		return
	}

	cert, err = asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	return
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
func ParseCRL(crlBytes []byte) (certList *pkix.CertificateList, err error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == pemType {
			crlBytes = block.Bytes
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL parses a DER encoded CRL from the given bytes.
func ParseDERCRL(derBytes []byte) (certList *pkix.CertificateList, err error) {
	certList = new(pkix.CertificateList)
	_, err = asn1.Unmarshal(derBytes, certList)
	if err != nil {
		certList = nil
	}
	return
}

// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
// contains the given list of revoked certificates.
//
// The only supported key type is RSA (*rsa.PrivateKey for priv).
func (c *Certificate) CreateCRL(rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("x509: non-RSA private keys not supported")
	}
	tbsCertList := pkix.TBSCertificateList{
		Version: 2,
		Signature: pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureSHA1WithRSA,
		},
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCerts,
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	h := sha1.New()
	h.Write(tbsCertListContents)
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand, rsaPriv, crypto.SHA1, digest)
	if err != nil {
		return
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList: tbsCertList,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureSHA1WithRSA,
		},
		SignatureValue: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Subject pkix.Name

	// Attributes is a collection of attributes providing
	// additional information about the subject of the certificate.
	// See RFC 2986 section 4.1.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains raw X.509 extensions. When parsing CSRs, this
	// can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled CSR. Values override any extensions that would otherwise
	// be produced based on the other fields but are overridden by any
	// extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated when parsing CSRs, see
	// Extensions.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  publicKeyInfo
	Attributes []pkix.AttributeTypeAndValueSET `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS#9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// CreateCertificateRequest creates a new certificate based on a template. The
// following members of template are used: Subject, Attributes,
// SignatureAlgorithm, Extensions, DNSNames, EmailAddresses, and IPAddresses.
// The private key is the private key of the signer.
//
// The returned slice is the certificate request in DER encoding.
//
// The only supported key types are RSA (*rsa.PrivateKey) and ECDSA
// (*ecdsa.PrivateKey).
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	hashFunc, sigAlgo, err := signingParamsForPrivateKey(priv, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(&priv.PublicKey)
	case *ecdsa.PrivateKey:
		publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(&priv.PublicKey)
	default:
		panic("internal error")
	}

	if err != nil {
		return nil, err
	}

	var extensions []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	extensions = append(extensions, template.ExtraExtensions...)

	var attributes []pkix.AttributeTypeAndValueSET
	attributes = append(attributes, template.Attributes...)

	if len(extensions) > 0 {
		// specifiedExtensions contains all the extensions that we
		// found specified via template.Attributes.
		specifiedExtensions := make(map[string]bool)

		for _, atvSet := range template.Attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) {
				continue
			}

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}
		}

		atvs := make([]pkix.AttributeTypeAndValue, 0, len(extensions))
		for _, e := range extensions {
			if specifiedExtensions[e.Id.String()] {
				// Attributes already contained a value for
				// this extension and it takes priority.
				continue
			}

			atvs = append(atvs, pkix.AttributeTypeAndValue{
				// There is no place for the critical flag in a CSR.
				Type:  e.Id,
				Value: e.Value,
			})
		}

		// Append the extensions to an existing attribute if possible.
		appended := false
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			atvSet.Value[0] = append(atvSet.Value[0], atvs...)
			appended = true
			break
		}

		// Otherwise, add a new attribute for the extensions.
		if !appended {
			attributes = append(attributes, pkix.AttributeTypeAndValueSET{
				Type: oidExtensionRequest,
				Value: [][]pkix.AttributeTypeAndValue{
					atvs,
				},
			})
		}
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		Attributes: attributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	h := hashFunc.New()
	h.Write(tbsCSRContents)
	digest := h.Sum(nil)

	var signature []byte
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand, priv, hashFunc, digest)
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand, priv, digest); err == nil {
			signature, err = asn1.Marshal(ecdsaSignature{r, s})
		}
	default:
		panic("internal error")
	}

	if err != nil {
		return
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, error) {
	out := &CertificateRequest{
		Raw: in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromOID(in.SignatureAlgorithm.Algorithm),

		PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version:    in.TBSCSR.Version,
		Attributes: in.TBSCSR.Attributes,
	}

	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	}

	out.Subject.FillFromRDNSequence(&subject)

	var extensions []pkix.AttributeTypeAndValue

	for _, atvSet := range in.TBSCSR.Attributes {
		if !atvSet.Type.Equal(oidExtensionRequest) {
			continue
		}

		for _, atvs := range atvSet.Value {
			extensions = append(extensions, atvs...)
		}
	}

	out.Extensions = make([]pkix.Extension, 0, len(extensions))

	for _, e := range extensions {
		value, ok := e.Value.([]byte)
		if !ok {
			return nil, errors.New("x509: extension attribute contained non-OCTET STRING data")
		}

		out.Extensions = append(out.Extensions, pkix.Extension{
			Id:    e.Type,
			Value: value,
		})

		if len(e.Type) == 4 && e.Type[0] == 2 && e.Type[1] == 5 && e.Type[2] == 29 {
			switch e.Type[3] {
			case 17:
				_, out.DNSNames, out.EmailAddresses, _, _, _, out.IPAddresses, _, err = parseGeneralNames(value)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return out, nil
}
