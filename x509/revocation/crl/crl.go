package crl

import (
	"encoding/asn1"
	"strconv"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// RevocationReasonCode - status codes that explain revocation reason see RFC 5280, Section 5.3.1
type RevocationReasonCode int

const (
	Unspecified          RevocationReasonCode = 0
	KeyCompromise        RevocationReasonCode = 1
	CACompromise         RevocationReasonCode = 2
	AffiliationChanged   RevocationReasonCode = 3
	Superseded           RevocationReasonCode = 4
	CessationOfOperation RevocationReasonCode = 5
	CertificateHold      RevocationReasonCode = 6
	// STATUS CODE 7 IS NOT USED
	RemoveFromCRL      RevocationReasonCode = 8
	PrivilegeWithdrawn RevocationReasonCode = 9
	AACompromise       RevocationReasonCode = 10
)

func (r RevocationReasonCode) String() string {
	switch r {
	case Unspecified:
		return "unspecified"
	case KeyCompromise:
		return "keyCompromise"
	case CACompromise:
		return "cACompromise"
	case AffiliationChanged:
		return "affiliationChanged"
	case Superseded:
		return "superseded"
	case CessationOfOperation:
		return "cessationOfOperation"
	case CertificateHold:
		return "certificateHold"
		// STATUS CODE 7 IS NOT USED
	case RemoveFromCRL:
		return "removeFromCRL"
	case PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case AACompromise:
		return "aACompromise"
	default:
		return "Unknown revocation reason code: " + strconv.Itoa(int(r))
	}
}

var (
	crlNumberExtensionOID        = asn1.ObjectIdentifier{2, 5, 29, 20}
	revocationReasonExtensionOID = asn1.ObjectIdentifier{2, 5, 29, 21}
	invalidityDateExtensionOID   = asn1.ObjectIdentifier{2, 5, 29, 24}
)

type crlNumberExtension struct {
	ID        asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	CRLNumber int
}

// TODO: handle additional CRL Extensions
// 2.5.29.21,cRLReason
// id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }
// -- reasonCode ::= { CRLReasonCode }

//2.5.29.24,invalidityDate
// id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }
// -- InvalidityDate ::=  GeneralizedTime

// RevocationData - information on whether a certificate has been
// revoked by a specified CRL, and information on the CRL
type RevocationData struct {
	CRLSignatureAlgorithm         x509.SignatureAlgorithm
	CRLSignatureValue             []byte
	Version                       int `asn1:"optional,default:0"`
	Issuer                        pkix.Name
	ThisUpdate                    time.Time
	NextUpdate                    time.Time `asn1:"optional"`
	CRLExtensions                 ListExtensionData
	UnknownCRLExtensions          []pkix.Extension `asn1:"tag:0,optional,explicit"`
	UnknownCriticalCRLExtensions  []pkix.Extension `asn1:"tag:0,optional,explicit"`
	IsRevoked                     bool
	RevocationTime                time.Time
	CertificateEntryExtensions    RevokedCertExtensionData
	RawCertificateEntryExtensions []pkix.Extension `asn1:"optional"`
}

// ListExtensionData - Data from optional, non-critical pkix.CertificateList extensions
type ListExtensionData struct {
	CRLNumber int
	AuthKeyID x509.SubjAuthKeyId `json:"authority_key_id,omitempty"`
}

// RevokedCertExtensionData - Data from optional, non-critical pkix.RevokedCertificate extensions
type RevokedCertExtensionData struct {
	Reason         string `json:"revocation_reason,omitempty"`
	invalidityDate time.Time
}

func gatherListExtensionInfo(certList *pkix.CertificateList, ret *RevocationData) {
	for _, extension := range certList.TBSCertList.Extensions {
		if extension.Id.Equal(crlNumberExtensionOID) {
			var ext crlNumberExtension
			asn1.Unmarshal(extension.Value, &ext.CRLNumber)
			ret.CRLExtensions.CRLNumber = ext.CRLNumber
		} else if extension.Critical {
			ret.UnknownCriticalCRLExtensions = append(ret.UnknownCriticalCRLExtensions, extension)
		} else {
			ret.UnknownCRLExtensions = append(ret.UnknownCRLExtensions, extension)
		}
	}
}

// CheckCRLForCert - parses through a given CRL and to see if a given certificate
// is present, and returns data on the revocation and CRL in general
func CheckCRLForCert(certList *pkix.CertificateList, cert *x509.Certificate) (*RevocationData, error) {
	ret := &RevocationData{
		CRLSignatureAlgorithm: x509.GetSignatureAlgorithmFromAI(certList.SignatureAlgorithm),
		CRLSignatureValue:     certList.SignatureValue.Bytes,
		Version:               certList.TBSCertList.Version,
		ThisUpdate:            certList.TBSCertList.ThisUpdate,
		NextUpdate:            certList.TBSCertList.NextUpdate,
		IsRevoked:             false,
	}
	ret.Issuer.FillFromRDNSequence(&certList.TBSCertList.Issuer)

	gatherListExtensionInfo(certList, ret)

	revokedCerts := certList.TBSCertList.RevokedCertificates
	for i := range revokedCerts {
		if revokedCerts[i].SerialNumber == cert.SerialNumber {
			ret.IsRevoked = true
			ret.RevocationTime = revokedCerts[i].RevocationTime
			break
		}
	}
	return ret, nil
}
