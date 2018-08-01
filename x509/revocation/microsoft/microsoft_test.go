package microsoft_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/revocation/microsoft"
)

// obtained from http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcert.sst
const disallowed_cert_location = `./test_disallowedcert.sst`

const revoked_intermediate = `
-----BEGIN CERTIFICATE-----
MIIEiDCCA3CgAwIBAgIEATFpsDANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJO
TDEeMBwGA1UEChMVU3RhYXQgZGVyIE5lZGVybGFuZGVuMSowKAYDVQQDEyFTdGFh
dCBkZXIgTmVkZXJsYW5kZW4gT3ZlcmhlaWQgQ0EwHhcNMDcwNzA1MDg0MjA3WhcN
MTUwNzI3MDgzOTQ2WjBfMQswCQYDVQQGEwJOTDEXMBUGA1UEChMORGlnaU5vdGFy
IEIuVi4xNzA1BgNVBAMTLkRpZ2lOb3RhciBQS0lvdmVyaGVpZCBDQSBPdmVyaGVp
ZCBlbiBCZWRyaWp2ZW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc
vdKnTmoKuzuiheF/AK2+tDBomAfNoHrElM9x+Yo35FPrV3bMi+Zs/u6HVcg+uwQ5
AKeAeKxbT370vbhUuHE7BzFJOZNUfCA7eSuPu2GQfbGs5h+QLp1FAalkLU3DL7nn
UNVOKlyrdnY3Rtd57EKZ96LspIlw3Dgrh6aqJOadkiQbvvb91C8ZF3rmMgeUVAVT
Q+lsvK9Hy7zL/b07RBKB8WtLu+20z6slTxjSzAL8o0+1QjPLWc0J3NNQ/aB2jKx+
ZopC9q0ckvO2+xRG603XLzDgbe5bNr5EdLcgBVeFTegAGaL2DOauocBC36esgl3H
aLcY5olLmmv6znn58yynAgMBAAGjggFQMIIBTDBIBgNVHSAEQTA/MD0GBFUdIAAw
NTAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5kaWdpbm90YXIubmwvY3BzL3BraW92
ZXJoZWlkMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMIGABgNVHSME
eTB3gBQLhtYPd6NosftkCcOIblwEHFfpPaFZpFcwVTELMAkGA1UEBhMCTkwxHjAc
BgNVBAoTFVN0YWF0IGRlciBOZWRlcmxhbmRlbjEmMCQGA1UEAxMdU3RhYXQgZGVy
IE5lZGVybGFuZGVuIFJvb3QgQ0GCBACYmnkwPQYDVR0fBDYwNDAyoDCgLoYsaHR0
cDovL2NybC5wa2lvdmVyaGVpZC5ubC9Eb21PdkxhdGVzdENSTC5jcmwwHQYDVR0O
BBYEFEwIyY128ZjHPt881y91DbF2eZfMMA0GCSqGSIb3DQEBBQUAA4IBAQAMlIca
v03jheLu19hjeQ5Q38aEW9K72fUxCho1l3TfFPoqDz7toOMI9tVOW6+mriXiRWsi
D7dUKH6S3o0UbNEc5W50BJy37zRERd/Jgx0ZH8Apad+J1T/CsFNt5U4X5HNhIxMm
cUP9TFnLw98iqiEr2b+VERqKpOKrp11Lbyn1UtHk0hWxi/7wA8+nfemZhzizDXMU
5HIs4c71rQZIZPrTKbmi2Lv01QulQERDjqC/zlqlUkxk0xcxYczopIro5Ij76eUv
BjMzm5RmZrGrUDqhCYF0U1onuabSJc/Tw6f/ltAv6uAejVLpGBwgCkegllYOQJBR
RKwa/fHuhR/3Qlpl
-----END CERTIFICATE-----
`

func parseCertPEM(t *testing.T) (revoked *x509.Certificate) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(revoked_intermediate))
	if !ok {
		t.Fail()
	}
	revoked = certPool.Certificates()[0]
	return
}

func loadRevokedList(t *testing.T) (disallowed *microsoft.DisallowedCerts) {
	sstFile, err := os.Open(disallowed_cert_location)
	if err != nil {
		t.Error(err.Error())
	}
	sstBytes, err := ioutil.ReadAll(sstFile)
	if err != nil {
		t.Error(err.Error())
	}
	sstFile.Close()
	disallowed, err = microsoft.Parse(sstBytes)
	if err != nil {
		t.Error(err.Error())
	}
	return
}

func TestParse(t *testing.T) {
	loadRevokedList(t)
}

func TestCheck(t *testing.T) {
	disallowed := loadRevokedList(t)
	revoked := parseCertPEM(t)
	entry := microsoft.Check(disallowed, revoked)
	if entry == nil { // this should provide an entry, since cert is revoked and in the provided sst file
		t.Fail()
	}
	if entry.SerialNumber.Cmp(revoked.SerialNumber) != 0 {
		t.Fail()
	}
}
