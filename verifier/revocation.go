package verifier

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
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

// CheckCRL - check whether the provided certificate has been revoked through
// a CRL. If no certList is provided, function will attempt to fetch it
// through the GetCRL function. If performing repeated calls to this function,
// independently calling GetCRL and caching the list between calls to
// CheckCRL is highly recommended (otherwise the CRL will be fetched on every
// single call to CheckCRL!).
func CheckCRL(c *x509.Certificate, certList *pkix.CertificateList) (isRevoked bool, err error) {
	if certList == nil {
		certList, err = GetCRL(c.CRLDistributionPoints[0])
	}
	if err != nil {
		return false, err
	}
	crlData, err := crl.CheckCRLForCert(certList, c, nil)
	if err != nil {
		return false, err
	}
	return crlData.IsRevoked, nil
}

// GetCRL - fetch and parse the CRL from the provided distrution point
func GetCRL(distributionPoint string) (*pkix.CertificateList, error) {
	if strings.HasPrefix(distributionPoint, "ldap") {
		return nil, errors.New("This CRL distributionPointribution point operates over LDAP - could not access")
	}

	crlResp, err := http.Get(distributionPoint)
	if err != nil {
		return nil, errors.New("failed to send HTTP Request for CRL: " + err.Error())
	}

	crlRespBody, err := ioutil.ReadAll(crlResp.Body)
	if err != nil {
		return nil, errors.New("Failed to read HTTP Response for CRL")
	}
	crlResp.Body.Close()

	certList, err := x509.ParseCRL(crlRespBody)
	if err != nil {
		return nil, errors.New("Failed to parse CRL" + err.Error())
	}
	return certList, nil
}
