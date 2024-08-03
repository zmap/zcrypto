package x509

import (
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

/* Certificate  ::=  SEQUENCE  {
	tbsCertificate       TBSCertificate,
	signatureAlgorithm   AlgorithmIdentifier,
	signature            BIT STRING  }

AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL  }
                                -- contains a value of the type
                                -- registered for use with the
                                -- algorithm object identifier value

TBSCertificate  ::=  SEQUENCE  {
	version         [0]  Version DEFAULT v1,
	serialNumber         CertificateSerialNumber,
	signature            AlgorithmIdentifier,
	issuer               Name,
	validity             Validity,
	subject              Name,
	subjectPublicKeyInfo SubjectPublicKeyInfo,
	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
						 -- If present, version MUST be v2 or v3
	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
						 -- If present, version MUST be v2 or v3
	extensions      [3]  Extensions OPTIONAL
						 -- If present, version MUST be v3 --  }
*/

// Certificate matches the core `Certificate` SEQUENCE from RFC 5280.
type Certificate struct {
	RawTBSCertificate []byte
	TBSCertificate    TBSCertificate

	RawSignatureAlgorithm []byte
	SignatureAlgorithm    AlgorithmIdentifier

	RawSignature []byte
	Signature    BitString
}

func ParseCertificate(b []byte) (*Certificate, error) {
	var c Certificate
	s := cryptobyte.String(b)

	var tbsCertificate, algorithmIdentifier, signature cryptobyte.String
	s.ReadASN1(&tbsCertificate, asn1.SEQUENCE)
	s.ReadASN1(&algorithmIdentifier, asn1.SEQUENCE)
	s.ReadASN1(&signature, asn1.BIT_STRING)

	c.RawTBSCertificate = tbsCertificate
	c.RawSignatureAlgorithm = algorithmIdentifier
	c.RawSignature = signature

	return &c, nil
}

type TBSCertificate struct {
	Version              int
	SerialNumber         CertificateSerialNumber
	Signature            AlgorithmIdentifier
	Issuer               Name
	Validity             Validity
	Subject              Name
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	IssuerUniqueID       UniqueIdentifier
	SubjectUniqueID      UniqueIdentifier
	Extensions           Extensions
}

type AlgorithmIdentifier struct {
	AlgorithmIdentifier ObjectIdentifier
	Parameters          Parameters
}

type BitString []byte
type CertificateSerialNumber []byte
type Name []byte
type Validity []byte
type SubjectPublicKeyInfo []byte
type UniqueIdentifier []byte
type Extensions []byte
type ObjectIdentifier []byte
type Parameters []byte
