package ocsp

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
)

// Request represents an OCSP request. See RFC 6960.
type Request struct {
	HashAlgorithm  crypto.Hash
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// https://tools.ietf.org/html/rfc2560#section-4.1.1
type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	RequestList   []request
}

type request struct {
	Cert certID
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

// Marshal marshals the OCSP request to ASN.1 DER encoded form.
func (req *Request) Marshal() ([]byte, error) {
	sha1HashOID := asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	return asn1.Marshal(ocspRequest{
		tbsRequest{
			Version: 0,
			RequestList: []request{
				{
					Cert: certID{
						pkix.AlgorithmIdentifier{
							Algorithm:  sha1HashOID,
							Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
						},
						req.IssuerNameHash,
						req.IssuerKeyHash,
						req.SerialNumber,
					},
				},
			},
		},
	})
}

// CreateRequest returns a DER-encoded, OCSP request for the status of cert
func CreateRequest(cert *x509.Certificate, issuer *x509.Certificate) ([]byte, error) {
	hashFunc := crypto.SHA1

	h := hashFunc.New()

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}

	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	req := &Request{
		HashAlgorithm:  hashFunc,
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   cert.SerialNumber,
	}
	return req.Marshal()
}

// Response represents an OCSP response. See RFC 6960.
type Response struct {
	// Status is one of {Good, Revoked, Unknown}
	CertificateStatus                             string
	SerialNumber                                  string
	ProducedAt, ThisUpdate, NextUpdate, RevokedAt time.Time
	RevocationReason                              string
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

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// ResponseStatus contains the result of an OCSP request. See
// https://tools.ietf.org/html/rfc6960#section-2.3
type ResponseStatus int

// Success - Response has valid confirmations
// Malformed - Illegal confirmation request
// InternalError - Internal Error in Issuer
// Trylater - Try Again Later
// SignatureRequired - Must Sign the Request
// Unauthorized - Request Unauthorized
// See https://tools.ietf.org/html/rfc6960#section-4.2.1
const (
	Success       ResponseStatus = 0
	Malformed     ResponseStatus = 1
	InternalError ResponseStatus = 2
	TryLater      ResponseStatus = 3
	// STATUS CODE 4 IS UNUSED IN OCSP
	SignatureRequired ResponseStatus = 5
	Unauthorized      ResponseStatus = 6
)

func (r ResponseStatus) String() string {
	switch r {
	case Success:
		return "success"
	case Malformed:
		return "malformed"
	case InternalError:
		return "internal error"
	case TryLater:
		return "try later"
	case SignatureRequired:
		return "signature required"
	case Unauthorized:
		return "unauthorized"
	default:
		return "unknown OCSP status: " + strconv.Itoa(int(r))
	}
}

// ResponseError respresents OCSP response status codes
type ResponseError struct {
	Status ResponseStatus
}

func (r ResponseError) Error() string {
	return "ocsp: error from server: " + r.Status.String()
}

var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
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
	var resp responseASN1
	rest, err := asn1.Unmarshal(bytes, &resp)
	if err != nil {
		fullErr := errors.New("This response is malformed: " + err.Error())
		return nil, fullErr
	}
	if len(rest) > 0 {
		err = errors.New("trailing data in OCSP response")
		return nil, err
	}

	if status := ResponseStatus(resp.Status); status != Success {
		badResponse := &Response{
			CertificateStatus: "OCSP Responder Error: " + status.String(),
		}
		return badResponse, nil
	}

	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		err = errors.New("bad OCSP response type")
		return nil, err
	}

	var basicResp basicResponse
	_, err = asn1.Unmarshal(resp.Response.Response, &basicResp)
	if err != nil {
		return nil, err
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 || cert == nil && n > 1 {
		err = errors.New("OCSP response contains bad number of responses")
		return nil, err
	}

	var singleResp singleResponse
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

	// Handle the ResponderID CHOICE tag. ResponderID can be flattened into
	// TBSResponseData once https://go-review.googlesource.com/34503 has been
	// released.
	rawResponderID := basicResp.TBSResponseData.RawResponderID
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

	if len(basicResp.Certificates) > 0 {
		// Responders should only send a single certificate (if they
		// send any) that connects the responder's certificate to the
		// original issuer. We accept responses with multiple
		// certificates due to a number responders sending them[1], but
		// ignore all but the first.
		//
		// [1] https://github.com/golang/go/issues/21527
		ret.ResponseIssuingCertificate, err = x509.ParseCertificate(basicResp.Certificates[0].FullBytes)
		if err != nil {
			return nil, err
		}

		if err = ret.CheckSignatureFrom(ret.ResponseIssuingCertificate); err != nil {
			err = errors.New("bad signature on embedded certificate: " + err.Error())
			return nil, err
		}

		if issuer != nil {
			if err = issuer.CheckSignature(ret.ResponseIssuingCertificate.SignatureAlgorithm, ret.ResponseIssuingCertificate.RawTBSCertificate, ret.ResponseIssuingCertificate.Signature); err != nil {
				ret.IsValidSignature = false
			} else {
				ret.IsValidSignature = true
			}
		}
	} else if issuer != nil {
		if err = ret.CheckSignatureFrom(issuer); err != nil {
			ret.IsValidSignature = false
		} else {
			ret.IsValidSignature = true
		}
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
	case bool(singleResp.Unknown):
		ret.CertificateStatus = "Unknown"
	default:
		ret.CertificateStatus = "Revoked"
		ret.RevokedAt = singleResp.Revoked.RevocationTime
		ret.RevocationReason = crl.RevocationReasonCode(singleResp.Revoked.Reason).String()
	}

	return ret, nil
}
