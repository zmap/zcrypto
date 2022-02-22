package crl

import (
	"encoding/json"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// RevocationReasonCode - status codes that explain revocation reason see RFC 5280, Section 5.3.1
type RevocationReasonCode int

var reasonCodeNames map[RevocationReasonCode]string

func init() {
	reasonCodeNames = make(map[RevocationReasonCode]string)
	reasonCodeNames[0] = "unspecified"
	reasonCodeNames[1] = "keyCompromise"
	reasonCodeNames[2] = "cACompromise"
	reasonCodeNames[3] = "affiliationChanged"
	reasonCodeNames[4] = "superseded"
	reasonCodeNames[5] = "cessationOfOperation"
	reasonCodeNames[6] = "certificateHold"
	// STATUS CODE 7 IS NOT USED
	reasonCodeNames[8] = "removeFromCRL"
	reasonCodeNames[9] = "privilegeWithdrawn"
	reasonCodeNames[10] = "aACompromise"
}

// MarshalJSON implements the json.Marshler interface
func (code *RevocationReasonCode) MarshalJSON() ([]byte, error) {
	aux := struct {
		Value int    `json:"value"`
		Name  string `json:"name"`
	}{
		Value: int(*code),
		Name:  code.String(),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (code *RevocationReasonCode) UnmarshalJSON(b []byte) error {
	aux := struct {
		Value int    `json:"value"`
		Name  string `json:"name"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*code = RevocationReasonCode(aux.Value)
	return nil
}

func (code *RevocationReasonCode) String() string {
	return reasonCodeNames[*code]
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
	Reason         *RevocationReasonCode
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
func CheckCRLForCert(certList *pkix.CertificateList, cert *x509.Certificate, cache map[string]*pkix.RevokedCertificate) (*RevocationData, error) {
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

	if cache != nil {
		if val, ok := cache[cert.SerialNumber.String()]; ok {
			ret.IsRevoked = true
			ret.RevocationTime = val.RevocationTime
		}
		return ret, nil
	}

	// else no cache was given, must linear search through
	revokedCerts := certList.TBSCertList.RevokedCertificates
	for i := range revokedCerts {
		if revokedCerts[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
			ret.IsRevoked = true
			ret.RevocationTime = revokedCerts[i].RevocationTime
			break
		}
	}
	return ret, nil
}
