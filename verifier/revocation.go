package verifier

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/revocation/ocsp"
)

// CheckOCSP - check the ocsp status of a provided certificate
// if issuer is not provided, function will attempt to fetch it
// through the AIA issuing field (which will then fail if this field is empty)
func CheckOCSP(c *x509.Certificate, issuer *x509.Certificate) (isRevoked bool, e error) {
	if issuer == nil {
		// get issuer certificate from OCSP info
		if c.IssuingCertificateURL == nil {
			return false, errors.New("This certificate does not list an issuing party")
		}

		issuerResp, err := http.Get(c.IssuingCertificateURL[0])
		if err != nil {
			return false, errors.New("failed to send HTTP Request for issuing certificate: " + err.Error())
		}

		issuerBody, err := ioutil.ReadAll(issuerResp.Body)
		if err != nil {
			return false, errors.New("Failed to read HTTP Response for issuing certificate" + err.Error())
		}
		issuerResp.Body.Close()

		issuer, err = x509.ParseCertificate(issuerBody)
		if err != nil {
			return false, errors.New("failed to parse issuer certificate PEM: " + err.Error())
		}
	}
	// create and send OCSP request
	keyHash, err := ocsp.GetKeyHashSHA1(issuer)
	nameHash := ocsp.GetNameHashSHA1(issuer)
	ocspRequestBytes, err := ocsp.CreateRequest(c, keyHash, nameHash)
	if err != nil {
		return false, errors.New("failed to construct OCSP request" + err.Error())
	}

	requestReader := bytes.NewReader(ocspRequestBytes)
	ocspHTTPResp, err := http.Post(c.OCSPServer[0], "application/ocsp-request", requestReader)
	if err != nil {
		return false, errors.New("Failed sending OCSP HTTP Request: " + err.Error())
	}

	ocspRespBytes, err := ioutil.ReadAll(ocspHTTPResp.Body)
	if err != nil {
		return false, errors.New("Failed reading OCSP HTTP Response" + err.Error())
	}
	ocspHTTPResp.Body.Close()

	ocspResp, err := ocsp.ParseResponseForCert(ocspRespBytes, c, issuer)
	if err != nil {
		return false, errors.New("Failed to parse OCSP Response: " + err.Error())
	}
	return ocspResp.IsRevoked, nil
}
