package google_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/revocation/google"
)

// obtained from https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records
const crlset_location = `./test_crlset`
const VERSION = "4619"

const revoked_intermediate = `
-----BEGIN CERTIFICATE-----
MIIHVTCCBT2gAwIBAgIIEOqAPvgqxt8wDQYJKoZIhvcNAQEFBQAwUTELMAkGA1UE
BhMCRVMxQjBABgNVBAMMOUF1dG9yaWRhZCBkZSBDZXJ0aWZpY2FjaW9uIEZpcm1h
cHJvZmVzaW9uYWwgQ0lGIEE2MjYzNDA2ODAeFw0xMzAyMjAxMDAzMTdaFw0zMDEy
MzEwNTA1NDJaMIGNMQswCQYDVQQGEwJFUzEeMBwGA1UEChMVRmlybWFwcm9mZXNp
b25hbCBTLkEuMRowGAYDVQQLExFTZWN1cml0eSBTZXJ2aWNlczESMBAGA1UEBRMJ
QTYyNjM0MDY4MS4wLAYDVQQDEyVBQyBGaXJtYXByb2Zlc2lvbmFsIC0gSU5GUkFF
U1RSVUNUVVJBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqX7V9RP
HmZ/SpGlhXSfREEtOiiRS8SdJC1QuOB2EYLiFEeL2QFZHIRP4HBm+CbLZ7ts+GLD
5XOGWa84Q9BgRI2HXF4E9PeCQh+ejtnnpDRQlx/cIkX5zt750xXfjArifVS4IUHR
fiyfZmNuyn3qqB5O/nz1K/YelKSZtbjc00qlwXU4sfrZRFJgm0PD6oxJqLoU8VVE
jBzdbVWsG9KEc91gG0u5UJZyLWGJP2f7I/zrki2WOf9SPfrA01viYw2PSe/81Z7O
tADKy076N6Z8ky4HaS1aNsqxx/LTylUh+9O0ccGKSQSpO87LFbrKNilGvIRQYzrj
ItUawGsF0KuUEwIDAQABo4IC8jCCAu4wdAYIKwYBBQUHAQEEaDBmMDYGCCsGAQUF
BzAChipodHRwOi8vY3JsLmZpcm1hcHJvZmVzaW9uYWwuY29tL2Nhcm9vdC5jcnQw
LAYIKwYBBQUHMAGGIGh0dHA6Ly9vY3NwLmZpcm1hcHJvZmVzaW9uYWwuY29tMB0G
A1UdDgQWBBRiFau1swh5pYf+gNki8I78jxH9eTASBgNVHRMBAf8ECDAGAQH/AgEA
MB8GA1UdIwQYMBaAFGXN66s1HgA+ftV0wBy0c0cOGmQvMIIB0gYDVR0gBIIByTCC
AcUwggHBBgorBgEEAeZ5CgoBMIIBsTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5m
aXJtYXByb2Zlc2lvbmFsLmNvbS9jcHMwggF8BggrBgEFBQcCAjCCAW4eggFqAEMA
ZQByAHQAaQBmAGkAYwBhAGQAbwAgAGQAZQAgAEEAdQB0AG8AcgBpAGQAYQBkACAA
ZABlACAAQwBlAHIAdABpAGYAaQBjAGEAYwBpAPMAbgAuACAAQwBvAG4AcwB1AGwA
dABlACAAbABhAHMAIABjAG8AbgBkAGkAYwBpAG8AbgBlAHMAIABkAGUAIAB1AHMA
bwAgAGUAbgAgAC8AIABDAGUAcgB0AGkAZgBpAGMAYQB0AGkAbwBuACAAQQB1AHQA
aABvAHIAaQB0AHkAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUALgAgAFMAZQBlACAA
dABlAHIAbQBzACAAYQBuAGQAIABjAG8AbgBkAGkAdABpAG8AbgBzACAAYQB0ACAA
IABoAHQAdABwADoALwAvAHcAdwB3AC4AZgBpAHIAbQBhAHAAcgBvAGYAZQBzAGkA
bwBuAGEAbAAuAGMAbwBtAC8AYwBwAHMwPAYDVR0fBDUwMzAxoC+gLYYraHR0cHM6
Ly9jcmwuZmlybWFwcm9mZXNpb25hbC5jb20vZnByb290LmNybDAOBgNVHQ8BAf8E
BAMCAQYwDQYJKoZIhvcNAQEFBQADggIBAGRD/ej1VKQGfWiBwL8I6plyFfvplmwO
+N7EpzUifUgn2sDHiL2L2V5nQdN2lLL5tI83JimPKybrHbv9EwSGPsTOgY+8HWCA
iaq9dLKVHRK93/FvI+Wj63X6pvx5YDiT2Kq7RuXQFx8AG+acwMa7WHaeravzAiSd
pak4qW5KlZ54RxiTNtFGwuEGpHc7wakdWSH3hUYfXNLz8JC9DmNqG8ZxAf3Z8AJq
vIeH4NRPkZ6//QG5JzPowb8eNG2v84ZYQStIAsHa0sVdq9o/zK9x2isv4Y+5GAw4
bnfq14G23Zh1oFS2T6la7W+AR3OGhP8Y6Xt+TFhn10yfE4TrFGNr20akj2TddsMj
SAatoB2gE3f7wTFsrXdJn0aJ/18KdlqV0NNuHrs/ZOIhnt7qswZVQfeQHHUQpwOp
CJrveDbSDZz3Kmo0afJtkcyAnZEPdFdyq8YgqfSqyJs6PJuemsj2ipai0gWO/3f8
EcApsll70fMRVXfOObBcO+hEO1tN0etNLlT5mlulpbMpkJ6hRgcHmVqogw1YJhmL
/E03f6Lw8aaCT9yDunE66bFZ/gwNky0V9PvCQni4GmGSKqcM2hFPux6FIWOOokBE
bicOgqIPCJodWamv++aE/6VKV6Th5gyYBJQ5Pjb6BRxpXtCVAVrev9ZIFcmYn6LX
wp6ggHtX2lGF
-----END CERTIFICATE-----
`

const PARENT_SPKI_HASH = `3b0d73b4be4a854adc3e51d7ef9fa48aefbb2cdd824d67bdc7d7d09a2abc2d43`

func parseCertPEM(t *testing.T) (revoked *x509.Certificate) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(revoked_intermediate))
	if !ok {
		t.Fail()
	}
	revoked = certPool.Certificates()[0]
	return
}

func loadRevokedList(t *testing.T) (crlset *google.CRLSet) {
	crlSetFile, err := os.Open(crlset_location)
	if err != nil {
		t.Error(err.Error())
	}

	crlSetBytes, err := ioutil.ReadAll(crlSetFile)
	if err != nil {
		t.Error(err.Error())
	}
	crlSetFile.Close()
	crlSetReadCloser := ioutil.NopCloser(bytes.NewReader(crlSetBytes))
	crlset, err = google.Parse(crlSetReadCloser, VERSION)
	if err != nil {
		t.Error(err.Error())
	}
	return
}

// Parses a static, stored version of an issued CRLSet - to prevent
// unexpected breakage with tests, use this instead of a live
// fetch when possible
func TestParse(t *testing.T) {
	loadRevokedList(t)
}

// just tests that there are no major complaints when live fetching,
// don't actually use this in case google removes our testing intermediate
// cert from the revocation list
func TestFetch(t *testing.T) {
	list, err := google.FetchAndParse()
	if list == nil || err != nil {
		t.Fail()
	}
}

func TestCheck(t *testing.T) {
	revoked := parseCertPEM(t)
	crlset := loadRevokedList(t)

	entry := crlset.Check(revoked, PARENT_SPKI_HASH)
	if entry == nil { // this should provide an entry, since cert is revoked and in the provided sst file
		t.Fail()
	}
	if entry.SerialNumber.Cmp(revoked.SerialNumber) != 0 {
		t.Fail()
	}
}
