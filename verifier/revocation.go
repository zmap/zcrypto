package verifier

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
	"github.com/zmap/zcrypto/x509/revocation/ocsp"
)

const (
	ocspReqContentType = "application/ocsp-request"
	ocspResContentType = "application/ocsp-response"
)

// CheckOCSP - check the ocsp status of a provided certificate
// if issuer is not provided, function will attempt to fetch it
// through the AIA issuing field (which will then fail if this field is empty)
func CheckOCSP(ctx context.Context, c *x509.Certificate, issuer *x509.Certificate) (isRevoked bool, info *RevocationInfo, e error) {
	if issuer == nil {
		// get issuer certificate from OCSP info
		if c.IssuingCertificateURL == nil {
			return false, nil, errors.New("This certificate does not list an issuing party")
		}

		res, err := httpGet(ctx, c.IssuingCertificateURL[0])
		if err != nil {
			return false, nil, errors.New("failed to send HTTP Request for issuing certificate: " + err.Error())
		}

		issuer, err = x509.ParseCertificate(res)
		if err != nil {
			return false, nil, errors.New("failed to parse issuer certificate PEM: " + err.Error())
		}
	}
	// create and send OCSP request
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	ocspRequestBytes, err := ocsp.CreateRequest(c, issuer, opts)
	if err != nil {
		return false, nil, errors.New("failed to construct OCSP request" + err.Error())
	}

	requestReader := bytes.NewReader(ocspRequestBytes)
	ocspRespBytes, err := httpPost(ctx, c.OCSPServer[0], ocspReqContentType, ocspResContentType, requestReader)
	if err != nil {
		return false, nil, errors.New("Failed sending OCSP HTTP Request: " + err.Error())
	}

	ocspResp, err := ocsp.ParseResponseForCert(ocspRespBytes, c, issuer)
	if err != nil {
		return false, nil, errors.New("Failed to parse OCSP Response: " + err.Error())
	}

	isRevoked = ocspResp.IsRevoked
	info = &RevocationInfo{
		NextUpdate: ocspResp.NextUpdate,
	}
	if isRevoked {
		info.RevocationTime = &ocspResp.RevokedAt
		info.Reason = ocspResp.RevocationReason
	}

	return
}

// CheckCRL - check whether the provided certificate has been revoked through
// a CRL. If no certList is provided, function will attempt to fetch it
// through the GetCRL function. If performing repeated calls to this function,
// independently calling GetCRL and caching the list between calls to
// CheckCRL is highly recommended (otherwise the CRL will be fetched on every
// single call to CheckCRL!).
func CheckCRL(ctx context.Context, c *x509.Certificate, certList *pkix.CertificateList) (isRevoked bool, info *RevocationInfo, err error) {
	if certList == nil {
		certList, err = GetCRL(ctx, c.CRLDistributionPoints[0])
	}
	if err != nil {
		return false, nil, err
	}
	crlData, err := crl.CheckCRLForCert(certList, c, nil)
	if err != nil {
		return false, nil, err
	}

	isRevoked = crlData.IsRevoked

	info = &RevocationInfo{
		NextUpdate: crlData.NextUpdate,
	}

	if isRevoked && crlData.CertificateEntryExtensions.Reason != nil {
		info.Reason = *crlData.CertificateEntryExtensions.Reason
		info.RevocationTime = &crlData.RevocationTime
	}

	return
}

// GetCRL - fetch and parse the CRL from the provided distrution point
func GetCRL(ctx context.Context, distributionPoint string) (*pkix.CertificateList, error) {
	if strings.HasPrefix(distributionPoint, "ldap") {
		return nil, errors.New("This CRL distributionPointribution point operates over LDAP - could not access")
	}

	crlRespBody, err := httpGet(ctx, distributionPoint)
	if err != nil {
		return nil, errors.New("failed to send HTTP Request for CRL: " + err.Error())
	}

	certList, err := x509.ParseCRL(crlRespBody)
	if err != nil {
		return nil, errors.New("failed to parse CRL" + err.Error())
	}
	return certList, nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func httpPost(ctx context.Context, url string, contentType, accept string, reqBody io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", accept)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
