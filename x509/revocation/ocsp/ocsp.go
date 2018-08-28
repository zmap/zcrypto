package ocsp

import (
	"crypto"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
)

// ResponseStatus contains the result of an OCSP request. See
// https://tools.ietf.org/html/rfc6960#section-2.3
type ResponseStatus int

// Success - OCSP Responder signals that response is successful
const Success ResponseStatus = 0

var responseStatusNames map[ResponseStatus]string
var hashOIDs map[crypto.Hash]asn1.ObjectIdentifier

func init() {
	responseStatusNames = make(map[ResponseStatus]string)
	responseStatusNames[0] = "success"
	responseStatusNames[1] = "malformedRequest"
	responseStatusNames[2] = "internalError"
	responseStatusNames[3] = "tryLater"
	responseStatusNames[5] = "sigRequired"
	responseStatusNames[6] = "unauthorized"

	hashOIDs = make(map[crypto.Hash]asn1.ObjectIdentifier)
	hashOIDs[crypto.SHA1] = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	hashOIDs[crypto.SHA256] = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	hashOIDs[crypto.SHA384] = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2})
	hashOIDs[crypto.SHA512] = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
}

// MarshalJSON implements the json.Marshler interface
func (code *ResponseStatus) MarshalJSON() ([]byte, error) {
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
func (code *ResponseStatus) UnmarshalJSON(b []byte) error {
	aux := struct {
		Value int    `json:"value"`
		Name  string `json:"name"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*code = ResponseStatus(aux.Value)
	return nil
}

func (code *ResponseStatus) String() string {
	return responseStatusNames[*code]
}

// RequestASN1 - corresponds to OCSPRequest struct in 4.1.1 of RFC 6960
type RequestASN1 struct {
	TBSRequest TBSRequest
	// optionalSignature - not used by this library
}

// TBSRequest - represents to-be-signed OCSP Request. See RFC 6960 4.1.1.
type TBSRequest struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	RequestList   []Request
	// requestExtensions - not used by this library
}

// Request - wrapper for single OCSP Request. See RFC 6960 4.1.1.
type Request struct {
	Cert CertID
	// singleRequestExtensions - not used by this library
}

// CertID - struct for ocsp data request for single cert. See RFC 6960 4.1.1
type CertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

// PublicKeyInfo - struct for public key data when creating hash, see GetKeyHash
// and RFC 6960
type PublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// GetKeyHashSHA1 - compute hash of the certificate's public key, using SHA-1
func GetKeyHashSHA1(cert *x509.Certificate) ([]byte, error) {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	var keyInfo PublicKeyInfo
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &keyInfo); err != nil {
		return nil, err
	}
	h.Write(keyInfo.PublicKey.RightAlign())
	return h.Sum(nil), nil
}

// GetNameHashSHA1 - compute hash of the certificate's subject field, using SHA-1
func GetNameHashSHA1(cert *x509.Certificate) []byte {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(cert.RawSubject)
	return h.Sum(nil)
}

// CreateRequest returns a DER-encoded, OCSP request for the status of cert
// keyhash and namehash must be computed with SHA-1, use functions above
func CreateRequest(cert *x509.Certificate, issuerKeyHash []byte, issuerNameHash []byte) ([]byte, error) {
	sha1HashOID := asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	algID := &pkix.AlgorithmIdentifier{
		Algorithm:  sha1HashOID,
		Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
	}

	certID := &CertID{
		HashAlgorithm: *algID,
		NameHash:      issuerNameHash,
		IssuerKeyHash: issuerKeyHash,
		SerialNumber:  cert.SerialNumber,
	}
	return asn1.Marshal(RequestASN1{
		TBSRequest{
			Version: 0,
			RequestList: []Request{
				{
					Cert: *certID,
				},
			},
		},
	})
}

// Response represents an OCSP response, flattened for easy manipulation
// of data. DOES NOT CORRESPOND TO TRUE OCSP RESPONSE STRUCTURE.
// API functions below parse OCSP responses and fill in this
// data structure for client use.
type Response struct {
	// Status is one of {Good, Revoked, Unknown}
	CertificateStatus                             string
	IsRevoked                                     bool // set to true if CertificateStatus is "revoked"
	SerialNumber                                  string
	ProducedAt, ThisUpdate, NextUpdate, RevokedAt time.Time
	RevocationReason                              crl.RevocationReasonCode
	ResponseIssuingCertificate                    *x509.Certificate
	// TBSResponseData contains the raw bytes of the signed response. If
	// Certificate is nil then this can be used to verify Signature.
	TBSResponseData    []byte
	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm
	IsValidSignature   bool

	// IssuerHash is the hash used to compute the IssuerNameHash and IssuerKeyHash.
	// Valid values are crypto.SHA1, crypto.SHA256, crypto.SHA384, and crypto.SHA512.
	// If zero, the default is crypto.SHA1.
	IssuerHash crypto.Hash

	// RawResponderName optionally contains the DER-encoded subject of the
	// responder certificate. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	RawResponderName []byte
	// ResponderKeyHash optionally contains the SHA-1 hash of the
	// responder's public key. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	ResponderKeyHash []byte

	// Extensions contains raw X.509 extensions from the singleExtensions field
	// of the OCSP response. When parsing certificates, this can be used to
	// extract non-critical extensions that are not parsed by this package. When
	// marshaling OCSP responses, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// OCSP response (in the singleExtensions field). Values override any
	// extensions that would otherwise be produced based on the other fields. The
	// ExtraExtensions field is not populated when parsing certificates, see
	// Extensions.
	ExtraExtensions []pkix.Extension
}

// The certificate status values that can be expressed in OCSP.  See RFC 6960.
// Good means that the certificate is valid.
// Revoked means that the certificate has been deliberately revoked.
// Unknown means that the OCSP responder doesn't know about the certificate.
// ServerFailed is unused and was never used (see
// https://go-review.googlesource.com/#/c/18944). ParseResponse will
// return a ResponseError when an error response is parsed.
const (
	Good = iota
	Revoked
	Unknown
	ServerFailed
)

// CheckSignatureFrom checks that the signature in resp is a valid signature
// from issuer. This should only be used if resp.Certificate is nil. Otherwise,
// the OCSP response contained an intermediate certificate that created the
// signature. That signature is checked by ParseResponse and only
// resp.Certificate remains to be validated.
func (resp *Response) CheckSignatureFrom(issuer *x509.Certificate) error {
	return issuer.CheckSignature(resp.SignatureAlgorithm, resp.TBSResponseData, resp.Signature)
}

// ResponseASN1 -  corresponds to OCSPResponse struct in 4.2.1 of RFC 6960
type ResponseASN1 struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  ResponseBytes `asn1:"explicit,tag:0,optional"`
}

// ResponseBytes - ASN1 struct for storing response data
type ResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// ResponseError respresents OCSP response status codes
type ResponseError struct {
	Status ResponseStatus
}

func (r ResponseError) Error() string {
	return "ocsp: error from server: " + r.Status.String()
}

// response type identifier for the basic-ocsp-response, see RFC 6960 4.2.1
var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

// BasicOCSPResponse - ASN1 struct for OCSP Response corresponding to
// idPKIXOCSPBasic, see RFC 6960 4.2.1
type BasicOCSPResponse struct {
	TBSResponseData    ResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// ResponseData - ASN1 struct defined in RFC 6960 4.2.1
type ResponseData struct {
	Raw            asn1.RawContent // added for our use
	Version        int             `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []SingleResponse
	// ResponseExtensions - unused by this library
}

// RevokedInfo - ASN1 struct defined in RFC 6960 4.2.1
type RevokedInfo struct {
	RevocationTime   time.Time       `asn1:"generalized"`
	RevocationReason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// SingleResponse - ASN1 struct defined in RFC 6960 4.2.1
type SingleResponse struct {
	CertID           CertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          RevokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// ValidateResponse - Checks to see that the signature on the OCSP resposne is valid
// From RFC 6960 Section 4.2.2.2:
// 		The key that signs a certificate's [OCSP Response] need not be the
// 		same key that signed the certificate.  It is necessary, however, to
// 		ensure that the entity signing this information is authorized to do
// 		so.  Therefore, a certificate's issuer MUST do one of the following:
// 						- sign the OCSP responses itself, or
// 						- explicitly designate this authority to another entity [delegation certificate]
//
// If a delegation certificate is used, it must be explicitly provided in
// the OCSP response. We parse this if provided and assign it
// to resp.ResponseIssuingCertificate
func ValidateResponse(resp *Response, basicResp *BasicOCSPResponse, issuer *x509.Certificate) bool {
	for _, certRaw := range basicResp.Certs { // if additional certs are provided (which could include a delegation cert)
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			return false
		} // delegation cert must be directly issued, so we only check certs[0]
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageOcspSigning { // this is a valid delegation certificate with id-kp-OCSPSigning authorization
				// check to see that OCSP resp has valid sig from delegation cert
				resp.ResponseIssuingCertificate = cert
				if err = resp.CheckSignatureFrom(cert); err != nil {
					err = errors.New("bad signature on embedded certificate: " + err.Error())
					return false
				}
				// check to see that delegation cert is signed by CA for original cert (target of OCSP query)
				err = issuer.CheckSignature(resp.ResponseIssuingCertificate.SignatureAlgorithm, resp.ResponseIssuingCertificate.RawTBSCertificate, resp.ResponseIssuingCertificate.Signature)
				return (err == nil)
			}
		} // if for loop completes, then none of the provided certs[] are delegation certs
	}
	// no delegation cert provided, check OCSP resp sig with original CA key
	err := resp.CheckSignatureFrom(issuer)
	return (err == nil)
}

// ParseResponse - Ensures that OCSP response ASN1 is properly formatted,
// performs basic error checking, then returns BasicResponse type
func ParseResponse(bytes []byte) (*BasicOCSPResponse, error) {
	var resp ResponseASN1
	rest, err := asn1.Unmarshal(bytes, &resp)
	if err != nil {
		fullErr := errors.New("This response is malformed: " + err.Error())
		return nil, fullErr
	}
	if len(rest) > 0 {
		err = errors.New("trailing data in OCSP response")
		return nil, err
	}

	if status := ResponseStatus(resp.ResponseStatus); status != Success {
		return nil, errors.New("OCSP Responder Error: " + status.String())
	}

	if !resp.ResponseBytes.ResponseType.Equal(idPKIXOCSPBasic) {
		err = errors.New("bad OCSP response type")
		return nil, err
	}

	var basicResp BasicOCSPResponse
	_, err = asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp)
	if err != nil {
		return nil, err
	}
	return &basicResp, nil
}

// ParseResponseForCert parses an OCSP response in DER form and searches for a
// Response relating to cert. If such a Response is found and the OCSP response
// contains a certificate then the signature over the response is checked. If
// issuer is not nil then it will be used to validate the signature or embedded
// certificate.
//
// Invalid responses and parse failures will result in a ParseError.
// Error responses will result in a ResponseError.
func ParseResponseForCert(bytes []byte, cert *x509.Certificate, issuer *x509.Certificate) (*Response, error) {
	basicResp, err := ParseResponse(bytes)
	if err != nil {
		return nil, err
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 || cert == nil && n > 1 {
		err = errors.New("OCSP response contains bad number of responses")
		return nil, err
	}

	// check to see if this OCSP response contains information about
	// the certificate in question (cert)
	var singleResp SingleResponse
	if cert == nil {
		singleResp = basicResp.TBSResponseData.Responses[0]
	} else {
		match := false
		for _, resp := range basicResp.TBSResponseData.Responses {
			if cert.SerialNumber.Cmp(resp.CertID.SerialNumber) == 0 {
				singleResp = resp
				match = true
				break
			}
		}
		if !match {
			err = errors.New("no response matching the supplied certificate")
			return nil, err
		}
	}

	ret := &Response{
		TBSResponseData:    basicResp.TBSResponseData.Raw,
		Signature:          basicResp.Signature.RightAlign(),
		SignatureAlgorithm: x509.GetSignatureAlgorithmFromAI(basicResp.SignatureAlgorithm),
		Extensions:         singleResp.SingleExtensions,
		SerialNumber:       singleResp.CertID.SerialNumber.String(),
		ProducedAt:         basicResp.TBSResponseData.ProducedAt,
		ThisUpdate:         singleResp.ThisUpdate,
		NextUpdate:         singleResp.NextUpdate,
	}

	if issuer != nil {
		ret.IsValidSignature = ValidateResponse(ret, basicResp, issuer)
	}

	// Handle the ResponderID CHOICE tag. ResponderID can be flattened into
	// TBSResponseData once https://go-review.googlesource.com/34503 has been
	// released.
	rawResponderID := basicResp.TBSResponseData.RawResponderID
	var rest []byte
	switch rawResponderID.Tag {
	case 1: // Name
		var rdn pkix.RDNSequence
		if rest, err = asn1.Unmarshal(rawResponderID.Bytes, &rdn); err != nil || len(rest) != 0 {
			err = errors.New("invalid responder name")
			return nil, err
		}
		ret.RawResponderName = rawResponderID.Bytes
	case 2: // KeyHash
		if rest, err = asn1.Unmarshal(rawResponderID.Bytes, &ret.ResponderKeyHash); err != nil || len(rest) != 0 {
			err = errors.New("invalid responder key hash")
			return nil, err
		}
	default:
		err = errors.New("invalid responder id tag")
		return nil, err
	}

	for _, ext := range singleResp.SingleExtensions {
		if ext.Critical {
			err = errors.New("unsupported critical extension")
			return ret, err
		}
	}

	for h, oid := range hashOIDs {
		if singleResp.CertID.HashAlgorithm.Algorithm.Equal(oid) {
			ret.IssuerHash = h
			break
		}
	}
	if ret.IssuerHash == 0 {
		err = errors.New("unsupported issuer hash algorithm")
		return ret, err
	}

	switch {
	case bool(singleResp.Good):
		ret.CertificateStatus = "Good"
		ret.IsRevoked = false
	case bool(singleResp.Unknown):
		ret.CertificateStatus = "Unknown"
		ret.IsRevoked = false
	default:
		ret.CertificateStatus = "Revoked"
		ret.IsRevoked = true
		ret.RevokedAt = singleResp.Revoked.RevocationTime
		ret.RevocationReason = crl.RevocationReasonCode(singleResp.Revoked.RevocationReason)
	}

	return ret, nil
}
