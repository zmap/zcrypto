package crl_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
)

const example_cert = `
-----BEGIN CERTIFICATE-----
MIIFLzCCBBegAwIBAgIQQFFpI7/egSZZtXZGsGlOJDANBgkqhkiG9w0BAQsFADB+
MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVj
IENsYXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MB4XDTE2MDgwMTAwMDAwMFoX
DTE4MDkzMDIzNTk1OVowgZIxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhJbGxpbm9p
czEQMA4GA1UEBwwHT2dsZXNieTEqMCgGA1UECgwhSWxsaW5vaXMgVmFsbGV5IENv
bW11bml0eSBDb2xsZWdlMRIwEAYDVQQLDAlCb29rc3RvcmUxHjAcBgNVBAMMFXd3
dy5pdmNjYm9va3N0b3JlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMUOWilh91JLixiaYMj9rtJPzAQh68Q/IrcmHZHH7NBeN4bBb2UwQTOpXjTw
boCdgVm1Ta4OOblk2kBLlZTHp0Zp6BYEZK3uAjmxe2NipvitFA0FkBuWJfC1Xj+S
nBjDwUqSskC92z6JnDzt3d2gZazmK69MdiuqYI2scgeCcGf2DeWvBnR+WHJ76O5d
rNcx/GvndIhqMBHd6b9yNyTsX8ZfxzCaWmIU36Z3GciWzaYV80hkBFDC4/TJ9dsS
2IW7POl8wHdzdBcHvOVYAVQKPpVRc1DQIIWQNalHHbKZ/J2SgM5G2v7ODv3eWxRM
uyzoSuBRksG+fxSUrz/QXfo9w3kCAwEAAaOCAZIwggGOMDMGA1UdEQQsMCqCFXd3
dy5pdmNjYm9va3N0b3JlLmNvbYIRaXZjY2Jvb2tzdG9yZS5jb20wCQYDVR0TBAIw
ADAOBgNVHQ8BAf8EBAMCBaAwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3NzLnN5
bWNiLmNvbS9zcy5jcmwwYQYDVR0gBFowWDBWBgZngQwBAgIwTDAjBggrBgEFBQcC
ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6
Ly9kLnN5bWNiLmNvbS9ycGEwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB8GA1UdIwQYMBaAFF9gz2GQVd+EQxSKYCqy9Xr0QxjvMFcGCCsGAQUFBwEBBEsw
STAfBggrBgEFBQcwAYYTaHR0cDovL3NzLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYa
aHR0cDovL3NzLnN5bWNiLmNvbS9zcy5jcnQwEwYKKwYBBAHWeQIEAwEB/wQCBQAw
DQYJKoZIhvcNAQELBQADggEBAJAl0wcd/QnYXtJc2PGkVMDneU29BYaSBZG4xaAU
8uWTspP+Nfb7UAcoT71oHpN8UFAiXQf1+bAorfofd1qQcZjUc5vAg04hK/r0ogI1
rLvBJe4/jW3BzFbpgNFl+I2cnY5eRz5ZL1EeKwDxpqK1gSLlTtqwkaiIynqdBCfX
lqDnqLozsE/vn2hNh3zc1zxj1Io36ALADtJOhw/HGlrabYlHh1o7XCm2/9y0scKH
rsfxMSV9FBVsbBJutTs3nfTGiMR4XISOueetlln3/2ZlNDfGXiXdy9D5/PnxbOqL
gGR2BKlwVlQR5rRkASVSMuNFHz2QN3Ddk0SQfR/aWGwiofU=
-----END CERTIFICATE-----`

const revoked_cert = `
-----BEGIN CERTIFICATE-----
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
g7YS
-----END CERTIFICATE-----`

const issuer_cert = `
-----BEGIN CERTIFICATE-----
MIIFODCCBCCgAwIBAgIQUT+5dDhwtzRAQY0wkwaZ/zANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTMxMDMxMDAwMDAwWhcNMjMxMDMwMjM1OTU5WjB+MQsw
CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVjIENs
YXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAstgFyhx0LbUXVjnFSlIJluhL2AzxaJ+aQihiw6UwU35VEYJb
A3oNL+F5BMm0lncZgQGUWfm893qZJ4Itt4PdWid/sgN6nFMl6UgfRk/InSn4vnlW
9vf92Tpo2otLgjNBEsPIPMzWlnqEIRoiBAMnF4scaGGTDw5RgDMdtLXO637QYqzu
s3sBdO9pNevK1T2p7peYyo2qRA4lmUoVlqTObQJUHypqJuIGOmNIrLRM0XWTUP8T
L9ba4cYY9Z/JJV3zADreJk20KQnNDz0jbxZKgRb78oMQw7jW2FUyPfG9D72MUpVK
Fpd6UiFjdS8W+cRmvvW1Cdj/JwDNRHxvSz+w9wIDAQABo4IBYzCCAV8wEgYDVR0T
AQH/BAgwBgEB/wIBADAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2Iu
Y29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAvBggrBgEFBQcBAQQjMCEw
HwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wawYDVR0gBGQwYjBgBgpg
hkgBhvhFAQc2MFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20v
Y3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vcnBhMCkG
A1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTUzNDAdBgNVHQ4E
FgQUX2DPYZBV34RDFIpgKrL1evRDGO8wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
Qzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEBAF6UVkndji1l9cE2UbYD49qecxny
H1mrWH5sJgUs+oHXXCMXIiw3k/eG7IXmsKP9H+IyqEVv4dn7ua/ScKAyQmW/hP4W
Ko8/xabWo5N9Q+l0IZE1KPRj6S7t9/Vcf0uatSDpCr3gRRAMFJSaXaXjS5HoJJtG
QGX0InLNmfiIEfXzf+YzguaoxX7+0AjiJVgIcWjmzaLmFN5OUiQt/eV5E1PnXi8t
TRttQBVSK/eHiXgSgW7ZTaoteNTCLD0IX4eRnh8OsN4wUmSGiaqdZpwOdgyA8nTY
Kvi4Os7X1g8RvmurFPW9QaAiY4nxug9vKWNmLT+sjHLF+8fk1A/yO0+MKcc=
-----END CERTIFICATE-----`

const test_crl_location = `./test_crl`

func parseCertPEM(t *testing.T) (cert *x509.Certificate, revoked *x509.Certificate, issuer *x509.Certificate) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(example_cert))
	if !ok {
		t.Fail()
	}
	ok = certPool.AppendCertsFromPEM([]byte(issuer_cert))
	if !ok {
		t.Fail()
	}
	ok = certPool.AppendCertsFromPEM([]byte(revoked_cert))
	if !ok {
		t.Fail()
	}
	cert = certPool.Certificates()[0]
	issuer = certPool.Certificates()[1]
	revoked = certPool.Certificates()[2]
	return
}

func testCerts(t *testing.T, certList *pkix.CertificateList, cache map[string]*pkix.RevokedCertificate) {
	cert, revoked, _ := parseCertPEM(t)
	// check non-revoked cert
	status, err := crl.CheckCRLForCert(certList, cert, cache)
	if err != nil {
		t.Error(err.Error())
	}
	if status.IsRevoked != false {
		t.Fail()
	}
	// check revoked cert
	status, err = crl.CheckCRLForCert(certList, revoked, cache)
	if err != nil {
		t.Error(err.Error())
	}
	if status.IsRevoked != true {
		t.Fail()
	}
}

func loadCRL(t *testing.T) (certList *pkix.CertificateList) {
	crlFile, err := os.Open(test_crl_location)
	if err != nil {
		t.Error(err.Error())
	}
	crlBytes, err := ioutil.ReadAll(crlFile)
	if err != nil {
		t.Error(err.Error())
	}
	crlFile.Close()
	certList, err = x509.ParseCRL(crlBytes)
	if err != nil {
		t.Error(err.Error())
	}
	return
}

func TestCRLParse(t *testing.T) {
	certList := loadCRL(t)
	testCerts(t, certList, nil)
}

func TestCRLParseWithCache(t *testing.T) {
	certList := loadCRL(t)
	cache := make(map[string]*pkix.RevokedCertificate)
	for _, cert := range certList.TBSCertList.RevokedCertificates {
		cache[cert.SerialNumber.String()] = &cert
	}
	testCerts(t, certList, cache)
}

func TestReasonCode(t *testing.T) {
	var status crl.RevocationReasonCode
	status = 0
	if status.String() != "unspecified" {
		t.Fail()
	}
	statusJson, err := status.MarshalJSON()
	if err != nil {
		t.Error(err.Error())
	}
	// test good unmarshal
	err = status.UnmarshalJSON(statusJson)
	if err != nil {
		t.Error(err.Error())
	}
	// test bad unmarshal
	err = status.UnmarshalJSON(statusJson[0:5]) // this should fail!
	if err == nil {
		t.Fail()
	}
}
