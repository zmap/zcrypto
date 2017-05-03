// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/pem"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509/pkix"
)

type verifyTest struct {
	leaf                 string
	intermediates        []string
	roots                []string
	currentTime          int64
	dnsName              string
	systemSkip           bool
	keyUsages            []ExtKeyUsage
	testSystemRootsError bool

	errorCallback  func(*testing.T, int, error) bool
	expectedChains [][]string
}

var verifyTests = []verifyTest{
	{
		leaf:                 googleLeaf,
		intermediates:        []string{giag2Intermediate},
		currentTime:          1395785200,
		dnsName:              "www.google.com",
		testSystemRootsError: true,

		// Without any roots specified we should get a system roots
		// error.
		errorCallback: expectSystemRootsError,
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "WwW.GooGLE.coM",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1,
		dnsName:       "WwW.GooGLE.coM",

		errorCallback: expectExpired,
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.example.com",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
		errorCallback: expectHostnameError,
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1,
		dnsName:       "www.example.com",

		errorCallback: expectExpired,
	},
	{
		leaf:        googleLeaf,
		roots:       []string{geoTrustRoot},
		currentTime: 1395785200,
		dnsName:     "www.google.com",

		// Skip when using systemVerify, since Windows
		// *will* find the missing intermediate cert.
		systemSkip:    true,
		errorCallback: expectAuthorityUnknown,
	},
	{
		leaf:          googleLeaf,
		intermediates: []string{geoTrustRoot, giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
		// CAPI doesn't build the chain with the duplicated GeoTrust
		// entry so the results don't match. Thus we skip this test
		// until that's fixed.
		systemSkip: true,
	},
	{
		leaf:          dnssecExpLeaf,
		intermediates: []string{startComIntermediate},
		roots:         []string{startComRoot},
		currentTime:   1302726541,

		expectedChains: [][]string{
			{"dnssec-exp", "StartCom Class 1", "StartCom Certification Authority"},
		},
	},
	{
		leaf:          dnssecExpLeaf,
		intermediates: []string{startComIntermediate, startComRoot},
		roots:         []string{startComRoot},
		currentTime:   1302726541,

		// Skip when using systemVerify, since Windows
		// can only return a single chain to us (for now).
		systemSkip: true,
		expectedChains: [][]string{
			{"dnssec-exp", "StartCom Class 1", "StartCom Certification Authority"},
		},
	},
	{
		leaf:          googleLeafWithInvalidHash,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		// The specific error message may not occur when using system
		// verification.
		systemSkip:    true,
		errorCallback: expectHashError,
	},
	{
		// The default configuration should reject an S/MIME chain.
		leaf:        smimeLeaf,
		roots:       []string{smimeIntermediate},
		currentTime: 1339436154,

		// Key usage not implemented for Windows yet.
		systemSkip:    true,
		errorCallback: expectUsageError,
	},
	{
		leaf:        smimeLeaf,
		roots:       []string{smimeIntermediate},
		currentTime: 1339436154,
		keyUsages:   []ExtKeyUsage{ExtKeyUsageServerAuth},

		// Key usage not implemented for Windows yet.
		systemSkip:    true,
		errorCallback: expectUsageError,
	},
	{
		leaf:        smimeLeaf,
		roots:       []string{smimeIntermediate},
		currentTime: 1339436154,
		keyUsages:   []ExtKeyUsage{ExtKeyUsageEmailProtection},

		// Key usage not implemented for Windows yet.
		systemSkip: true,
		expectedChains: [][]string{
			{"Ryan Hurst", "GlobalSign PersonalSign 2 CA - G2"},
		},
	},
	{
		leaf:          megaLeaf,
		intermediates: []string{comodoIntermediate1},
		roots:         []string{comodoRoot},
		currentTime:   1360431182,

		// CryptoAPI can find alternative validation paths so we don't
		// perform this test with system validation.
		systemSkip: true,
		expectedChains: [][]string{
			{"mega.co.nz", "EssentialSSL CA", "COMODO Certification Authority"},
		},
	},
	{
		// Check that a name constrained intermediate works even when
		// it lists multiple constraints.
		leaf:          nameConstraintsLeaf,
		intermediates: []string{nameConstraintsIntermediate1, nameConstraintsIntermediate2},
		roots:         []string{globalSignRoot},
		currentTime:   1382387896,
		dnsName:       "secure.iddl.vt.edu",

		expectedChains: [][]string{
			{
				"Technology-enhanced Learning and Online Strategies",
				"Virginia Tech Global Qualified Server CA",
				"Trusted Root CA G2",
				"GlobalSign Root CA",
			},
		},
	},
	{
		// Check that SHA-384 intermediates (which are popping up)
		// work.
		leaf:          moipLeafCert,
		intermediates: []string{comodoIntermediateSHA384, comodoRSAAuthority},
		roots:         []string{addTrustRoot},
		currentTime:   1397502195,
		dnsName:       "api.moip.com.br",

		expectedChains: [][]string{
			{
				"api.moip.com.br",
				"COMODO RSA Extended Validation Secure Server CA",
				"COMODO RSA Certification Authority",
				"AddTrust External CA Root",
			},
		},
	},
	{
		// Check the NotAfter < NotBefore is NeverValid
		leaf:          zcryptoNeverValid,
		intermediates: []string{zcryptoIntermediate},
		roots:         []string{zcryptoRoot},
		currentTime:   1622505600, // Tuesday 1st June 2021 12:00:00 AM
		dnsName:       "never-valid.example.com",

		errorCallback: expectNeverValid,
	},
	{
		leaf:          zcryptoValidBeforeIntermediate,
		intermediates: []string{zcryptoIntermediate},
		roots:         []string{zcryptoRoot},
		currentTime:   1527811200, // Friday 1st June 2018 12:00:00 AM
		dnsName:       "never-valid.example.com",

		errorCallback: expectNeverValid,
	},
}

func expectHostnameError(t *testing.T, i int, err error) (ok bool) {
	if _, ok := err.(HostnameError); !ok {
		t.Errorf("#%d: error was not a HostnameError: %s", i, err)
		return false
	}
	return true
}

func expectExpired(t *testing.T, i int, err error) (ok bool) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != Expired {
		t.Errorf("#%d: error was not Expired: %s", i, err)
		return false
	}
	return true
}

func expectNeverValid(t *testing.T, i int, err error) (ok bool) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != NeverValid {
		t.Errorf("#%d: error was not NeverValid: %s", i, err)
		return false
	}
	return true
}

func expectUsageError(t *testing.T, i int, err error) (ok bool) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != IncompatibleUsage {
		t.Errorf("#%d: error was not IncompatibleUsage: %s", i, err)
		return false
	}
	return true
}

func expectAuthorityUnknown(t *testing.T, i int, err error) (ok bool) {
	if _, ok := err.(UnknownAuthorityError); !ok {
		t.Errorf("#%d: error was not UnknownAuthorityError: %s", i, err)
		return false
	}
	return true
}

func expectSystemRootsError(t *testing.T, i int, err error) bool {
	if _, ok := err.(SystemRootsError); !ok {
		t.Errorf("#%d: error was not SystemRootsError: %s", i, err)
		return false
	}
	return true
}

func expectHashError(t *testing.T, i int, err error) bool {
	if err == nil {
		t.Errorf("#%d: no error resulted from invalid hash", i)
		return false
	}
	if expected := "algorithm unimplemented"; !strings.Contains(err.Error(), expected) {
		t.Errorf("#%d: error resulting from invalid hash didn't contain '%s', rather it was: %s", i, expected, err)
		return false
	}
	return true
}

func certificateFromPEM(pemBytes string) (*Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return ParseCertificate(block.Bytes)
}

func testVerify(t *testing.T, useSystemRoots bool) {
	for i, test := range verifyTests {
		if useSystemRoots && test.systemSkip {
			continue
		}
		if runtime.GOOS == "windows" && test.testSystemRootsError {
			continue
		}

		opts := VerifyOptions{
			Intermediates: NewCertPool(),
			DNSName:       test.dnsName,
			CurrentTime:   time.Unix(test.currentTime, 0),
			KeyUsages:     test.keyUsages,
		}

		if !useSystemRoots {
			opts.Roots = NewCertPool()
			for j, root := range test.roots {
				ok := opts.Roots.AppendCertsFromPEM([]byte(root))
				if !ok {
					t.Errorf("#%d: failed to parse root #%d", i, j)
					return
				}
			}
		}

		for j, intermediate := range test.intermediates {
			ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
			if !ok {
				t.Errorf("#%d: failed to parse intermediate #%d", i, j)
				return
			}
		}

		leaf, err := certificateFromPEM(test.leaf)
		if err != nil {
			t.Errorf("#%d: failed to parse leaf: %s", i, err)
			return
		}

		var oldSystemRoots *CertPool
		if test.testSystemRootsError {
			oldSystemRoots = systemRootsPool()
			systemRoots = nil
			opts.Roots = nil
		}

		chains, _, _, err := leaf.Verify(opts)

		if test.testSystemRootsError {
			systemRoots = oldSystemRoots
		}

		if test.errorCallback == nil && err != nil {
			t.Errorf("#%d: unexpected error: %s", i, err)
		}
		if test.errorCallback != nil {
			if !test.errorCallback(t, i, err) {
				return
			}
		}

		if len(chains) != len(test.expectedChains) {
			t.Errorf("#%d: wanted %d chains, got %d", i, len(test.expectedChains), len(chains))
		}

		// We check that each returned chain matches a chain from
		// expectedChains but an entry in expectedChains can't match
		// two chains.
		seenChains := make([]bool, len(chains))
	NextOutputChain:
		for _, chain := range chains {
		TryNextExpected:
			for j, expectedChain := range test.expectedChains {
				if seenChains[j] {
					continue
				}
				if len(chain) != len(expectedChain) {
					continue
				}
				for k, cert := range chain {
					if strings.Index(nameToKey(&cert.Subject), expectedChain[k]) == -1 {
						continue TryNextExpected
					}
				}
				// we matched
				seenChains[j] = true
				continue NextOutputChain
			}
			t.Errorf("#%d: No expected chain matched %s", i, chainToDebugString(chain))
		}
	}
}

func TestGoVerify(t *testing.T) {
	testVerify(t, false)
}

func TestSystemVerify(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("skipping verify test using system APIs on %q", runtime.GOOS)
	}

	testVerify(t, true)
}

func chainToDebugString(chain []*Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

func nameToKey(name *pkix.Name) string {
	return strings.Join(name.Country, ",") + "/" + strings.Join(name.Organization, ",") + "/" + strings.Join(name.OrganizationalUnit, ",") + "/" + name.CommonName
}

const geoTrustRoot = `-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----
`

const giag2Intermediate = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----
`

const googleLeaf = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----
`

// googleLeafWithInvalidHash is the same as googleLeaf, but the signature
// algorithm in the certificate contains a nonsense OID.
const googleLeafWithInvalidHash = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAWAFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQFgBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----
`

const dnssecExpLeaf = `-----BEGIN CERTIFICATE-----
MIIGzTCCBbWgAwIBAgIDAdD6MA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJ
TDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0
YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3Mg
MSBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTAwNzA0MTQ1MjQ1
WhcNMTEwNzA1MTA1NzA0WjCBwTEgMB4GA1UEDRMXMjIxMTM3LWxpOWE5dHhJRzZM
NnNyVFMxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVQZXJzb25hIE5vdCBWYWxpZGF0
ZWQxKTAnBgNVBAsTIFN0YXJ0Q29tIEZyZWUgQ2VydGlmaWNhdGUgTWVtYmVyMRsw
GQYDVQQDExJ3d3cuZG5zc2VjLWV4cC5vcmcxKDAmBgkqhkiG9w0BCQEWGWhvc3Rt
YXN0ZXJAZG5zc2VjLWV4cC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDEdF/22vaxrPbqpgVYMWi+alfpzBctpbfLBdPGuqOazJdCT0NbWcK8/+B4
X6OlSOURNIlwLzhkmwVsWdVv6dVSaN7d4yI/fJkvgfDB9+au+iBJb6Pcz8ULBfe6
D8HVvqKdORp6INzHz71z0sghxrQ0EAEkoWAZLh+kcn2ZHdcmZaBNUfjmGbyU6PRt
RjdqoP+owIaC1aktBN7zl4uO7cRjlYFdusINrh2kPP02KAx2W84xjxX1uyj6oS6e
7eBfvcwe8czW/N1rbE0CoR7h9+HnIrjnVG9RhBiZEiw3mUmF++Up26+4KTdRKbu3
+BL4yMpfd66z0+zzqu+HkvyLpFn5AgMBAAGjggL/MIIC+zAJBgNVHRMEAjAAMAsG
A1UdDwQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUy04I5guM
drzfh2JQaXhgV86+4jUwHwYDVR0jBBgwFoAU60I00Jiwq5/0G2sI98xkLu8OLEUw
LQYDVR0RBCYwJIISd3d3LmRuc3NlYy1leHAub3Jngg5kbnNzZWMtZXhwLm9yZzCC
AUIGA1UdIASCATkwggE1MIIBMQYLKwYBBAGBtTcBAgIwggEgMC4GCCsGAQUFBwIB
FiJodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kucGRmMDQGCCsGAQUFBwIB
FihodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9pbnRlcm1lZGlhdGUucGRmMIG3Bggr
BgEFBQcCAjCBqjAUFg1TdGFydENvbSBMdGQuMAMCAQEagZFMaW1pdGVkIExpYWJp
bGl0eSwgc2VlIHNlY3Rpb24gKkxlZ2FsIExpbWl0YXRpb25zKiBvZiB0aGUgU3Rh
cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUG9saWN5IGF2YWlsYWJsZSBh
dCBodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kucGRmMGEGA1UdHwRaMFgw
KqAooCaGJGh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL2NydDEtY3JsLmNybDAqoCig
JoYkaHR0cDovL2NybC5zdGFydHNzbC5jb20vY3J0MS1jcmwuY3JsMIGOBggrBgEF
BQcBAQSBgTB/MDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5zdGFydHNzbC5jb20v
c3ViL2NsYXNzMS9zZXJ2ZXIvY2EwQgYIKwYBBQUHMAKGNmh0dHA6Ly93d3cuc3Rh
cnRzc2wuY29tL2NlcnRzL3N1Yi5jbGFzczEuc2VydmVyLmNhLmNydDAjBgNVHRIE
HDAahhhodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS8wDQYJKoZIhvcNAQEFBQADggEB
ACXj6SB59KRJPenn6gUdGEqcta97U769SATyiQ87i9er64qLwvIGLMa3o2Rcgl2Y
kghUeyLdN/EXyFBYA8L8uvZREPoc7EZukpT/ZDLXy9i2S0jkOxvF2fD/XLbcjGjM
iEYG1/6ASw0ri9C0k4oDDoJLCoeH9++yqF7SFCCMcDkJqiAGXNb4euDpa8vCCtEQ
CSS+ObZbfkreRt3cNCf5LfCXe9OsTnCfc8Cuq81c0oLaG+SmaLUQNBuToq8e9/Zm
+b+/a3RVjxmkV5OCcGVBxsXNDn54Q6wsdw0TBMcjwoEndzpLS7yWgFbbkq5ZiGpw
Qibb2+CfKuQ+WFV1GkVQmVA=
-----END CERTIFICATE-----`

const startComIntermediate = `-----BEGIN CERTIFICATE-----
MIIGNDCCBBygAwIBAgIBGDANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDcxMDI0MjA1NDE3WhcNMTcxMDI0MjA1NDE3WjCB
jDELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKzApBgNVBAsT
IlNlY3VyZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxODA2BgNVBAMTL1N0
YXJ0Q29tIENsYXNzIDEgUHJpbWFyeSBJbnRlcm1lZGlhdGUgU2VydmVyIENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtonGrO8JUngHrJJj0PREGBiE
gFYfka7hh/oyULTTRwbw5gdfcA4Q9x3AzhA2NIVaD5Ksg8asWFI/ujjo/OenJOJA
pgh2wJJuniptTT9uYSAK21ne0n1jsz5G/vohURjXzTCm7QduO3CHtPn66+6CPAVv
kvek3AowHpNz/gfK11+AnSJYUq4G2ouHI2mw5CrY6oPSvfNx23BaKA+vWjhwRRI/
ME3NO68X5Q/LoKldSKqxYVDLNM08XMML6BDAjJvwAwNi/rJsPnIO7hxDKslIDlc5
xDEhyBDBLIf+VJVSH1I8MRKbf+fAoKVZ1eKPPvDVqOHXcDGpxLPPr21TLwb0pwID
AQABo4IBrTCCAakwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0OBBYEFOtCNNCYsKuf9BtrCPfMZC7vDixFMB8GA1UdIwQYMBaAFE4L7xqkQFul
F2mHMMo0aEPQQa7yMGYGCCsGAQUFBwEBBFowWDAnBggrBgEFBQcwAYYbaHR0cDov
L29jc3Auc3RhcnRzc2wuY29tL2NhMC0GCCsGAQUFBzAChiFodHRwOi8vd3d3LnN0
YXJ0c3NsLmNvbS9zZnNjYS5jcnQwWwYDVR0fBFQwUjAnoCWgI4YhaHR0cDovL3d3
dy5zdGFydHNzbC5jb20vc2ZzY2EuY3JsMCegJaAjhiFodHRwOi8vY3JsLnN0YXJ0
c3NsLmNvbS9zZnNjYS5jcmwwgYAGA1UdIAR5MHcwdQYLKwYBBAGBtTcBAgEwZjAu
BggrBgEFBQcCARYiaHR0cDovL3d3dy5zdGFydHNzbC5jb20vcG9saWN5LnBkZjA0
BggrBgEFBQcCARYoaHR0cDovL3d3dy5zdGFydHNzbC5jb20vaW50ZXJtZWRpYXRl
LnBkZjANBgkqhkiG9w0BAQUFAAOCAgEAIQlJPqWIbuALi0jaMU2P91ZXouHTYlfp
tVbzhUV1O+VQHwSL5qBaPucAroXQ+/8gA2TLrQLhxpFy+KNN1t7ozD+hiqLjfDen
xk+PNdb01m4Ge90h2c9W/8swIkn+iQTzheWq8ecf6HWQTd35RvdCNPdFWAwRDYSw
xtpdPvkBnufh2lWVvnQce/xNFE+sflVHfXv0pQ1JHpXo9xLBzP92piVH0PN1Nb6X
t1gW66pceG/sUzCv6gRNzKkC4/C2BBL2MLERPZBOVmTX3DxDX3M570uvh+v2/miI
RHLq0gfGabDBoYvvF0nXYbFFSF87ICHpW7LM9NfpMfULFWE7epTj69m8f5SuauNi
YpaoZHy4h/OZMn6SolK+u/hlz8nyMPyLwcKmltdfieFcNID1j0cHL7SRv7Gifl9L
WtBbnySGBVFaaQNlQ0lxxeBvlDRr9hvYqbBMflPrj0jfyjO1SPo2ShpTpjMM0InN
SRXNiTE8kMBy12VLUjWKRhFEuT2OKGWmPnmeXAhEKa2wNREuIU640ucQPl2Eg7PD
wuTSxv0JS3QJ3fGz0xk+gA2iCxnwOOfFwq/iI9th4p1cbiCJSS4jarJiwUW0n6+L
p/EiO/h94pDQehn7Skzj0n1fSoMD7SfWI55rjbRZotnvbIIp3XUZPD9MEI3vu3Un
0q6Dp6jOW6c=
-----END CERTIFICATE-----`

const startComRoot = `-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0NjM2WhcNMzYwOTE3MTk0NjM2WjB9
MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMi
U2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3Rh
cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZk
pMyONvg45iPwbm2xPN1yo4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rf
OQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/C
Ji/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/deMotHweXMAEtcnn6RtYT
Kqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt2PZE4XNi
HzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMM
Av+Z6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w
+2OqqGwaVLRcJXrJosmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+
Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3
Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVcUjyJthkqcwEKDwOzEmDyei+B
26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT37uMdBNSSwID
AQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE
FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9j
ZXJ0LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3Js
LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFM
BgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUHAgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0
Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRwOi8vY2VydC5zdGFy
dGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYgU3Rh
cnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlh
YmlsaXR5LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2Yg
dGhlIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFp
bGFibGUgYXQgaHR0cDovL2NlcnQuc3RhcnRjb20ub3JnL3BvbGljeS5wZGYwEQYJ
YIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilTdGFydENvbSBGcmVlIFNT
TCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOCAgEAFmyZ
9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8
jhvh3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUW
FjgKXlf2Ysd6AgXmvB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJz
ewT4F+irsfMuXGRuczE6Eri8sxHkfY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1
ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3fsNrarnDy0RLrHiQi+fHLB5L
EUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZEoalHmdkrQYu
L6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq
yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuC
O3NJo2pXh5Tl1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6V
um0ABj6y6koQOdjQK/W/7HW/lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkySh
NOsF/5oirpt9P/FlUQqmMGqz9IgcgA38corog14=
-----END CERTIFICATE-----`

const startComRootSHA256 = `-----BEGIN CERTIFICATE-----
MIIHhzCCBW+gAwIBAgIBLTANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0NjM3WhcNMzYwOTE3MTk0NjM2WjB9
MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMi
U2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3Rh
cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZk
pMyONvg45iPwbm2xPN1yo4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rf
OQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/C
Ji/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/deMotHweXMAEtcnn6RtYT
Kqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt2PZE4XNi
HzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMM
Av+Z6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w
+2OqqGwaVLRcJXrJosmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+
Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3
Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVcUjyJthkqcwEKDwOzEmDyei+B
26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT37uMdBNSSwID
AQABo4ICEDCCAgwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0OBBYEFE4L7xqkQFulF2mHMMo0aEPQQa7yMB8GA1UdIwQYMBaAFE4L7xqkQFul
F2mHMMo0aEPQQa7yMIIBWgYDVR0gBIIBUTCCAU0wggFJBgsrBgEEAYG1NwEBATCC
ATgwLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL3BvbGljeS5w
ZGYwNAYIKwYBBQUHAgEWKGh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL2ludGVybWVk
aWF0ZS5wZGYwgc8GCCsGAQUFBwICMIHCMCcWIFN0YXJ0IENvbW1lcmNpYWwgKFN0
YXJ0Q29tKSBMdGQuMAMCAQEagZZMaW1pdGVkIExpYWJpbGl0eSwgcmVhZCB0aGUg
c2VjdGlvbiAqTGVnYWwgTGltaXRhdGlvbnMqIG9mIHRoZSBTdGFydENvbSBDZXJ0
aWZpY2F0aW9uIEF1dGhvcml0eSBQb2xpY3kgYXZhaWxhYmxlIGF0IGh0dHA6Ly93
d3cuc3RhcnRzc2wuY29tL3BvbGljeS5wZGYwEQYJYIZIAYb4QgEBBAQDAgAHMDgG
CWCGSAGG+EIBDQQrFilTdGFydENvbSBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAgEAjo/n3JR5fPGFf59Jb2vKXfuM/gTF
wWLRfUKKvFO3lANmMD+x5wqnUCBVJX92ehQN6wQOQOY+2IirByeDqXWmN3PH/UvS
Ta0XQMhGvjt/UfzDtgUx3M2FIk5xt/JxXrAaxrqTi3iSSoX4eA+D/i+tLPfkpLst
0OcNOrg+zvZ49q5HJMqjNTbOx8aHmNrs++myziebiMMEofYLWWivydsQD032ZGNc
pRJvkrKTlMeIFw6Ttn5ii5B/q06f/ON1FE8qMt9bDeD1e5MNq6HPh+GlBEXoPBKl
CcWw0bdT82AUuoVpaiF8H3VhFyAXe2w7QSlc4axa0c2Mm+tgHRns9+Ww2vl5GKVF
P0lDV9LdJNUso/2RjSe15esUBppMeyG7Oq0wBhjA2MFrLH9ZXF2RsXAiV+uKa0hK
1Q8p7MZAwC+ITGgBF3f0JBlPvfrhsiAhS90a2Cl9qrjeVOwhVYBsHvUwyKMQ5bLm
KhQxw4UtjJixhlpPiVktucf3HMiKf8CdBUrmQk9io20ppB+Fq9vlgcitKj1MXVuE
JnHEhV5xJMqlG2zYYdMa4FTbzrqpMrUi9nNBCV24F10OD5mQ1kfabwo6YigUZ4LZ
8dCAWZvLMdibD4x3TrVoivJs9iQOLWxwxXPR3hTQcY+203sC9uO41Alua551hDnm
fyWl8kgAwKQB2j8=
-----END CERTIFICATE-----`

const smimeLeaf = `-----BEGIN CERTIFICATE-----
MIIFBjCCA+6gAwIBAgISESFvrjT8XcJTEe6rBlPptILlMA0GCSqGSIb3DQEBBQUA
MFQxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYD
VQQDEyFHbG9iYWxTaWduIFBlcnNvbmFsU2lnbiAyIENBIC0gRzIwHhcNMTIwMTIz
MTYzNjU5WhcNMTUwMTIzMTYzNjU5WjCBlDELMAkGA1UEBhMCVVMxFjAUBgNVBAgT
DU5ldyBIYW1zcGhpcmUxEzARBgNVBAcTClBvcnRzbW91dGgxGTAXBgNVBAoTEEds
b2JhbFNpZ24sIEluYy4xEzARBgNVBAMTClJ5YW4gSHVyc3QxKDAmBgkqhkiG9w0B
CQEWGXJ5YW4uaHVyc3RAZ2xvYmFsc2lnbi5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC4ASSTvavmsFQAob60ukSSwOAL9nT/s99ltNUCAf5fPH5j
NceMKxaQse2miOmRRIXaykcq1p/TbI70Ztce38r2mbOwqDHHPVi13GxJEyUXWgaR
BteDMu5OGyWNG1kchVsGWpbstT0Z4v0md5m1BYFnxB20ebJyOR2lXDxsFK28nnKV
+5eMj76U8BpPQ4SCH7yTMG6y0XXsB3cCrBKr2o3TOYgEKv+oNnbaoMt3UxMt9nSf
9jyIshjqfnT5Aew3CUNMatO55g5FXXdIukAweg1YSb1ls05qW3sW00T3d7dQs9/7
NuxCg/A2elmVJSoy8+MLR8JSFEf/aMgjO/TyLg/jAgMBAAGjggGPMIIBizAOBgNV
HQ8BAf8EBAMCBaAwTQYDVR0gBEYwRDBCBgorBgEEAaAyASgKMDQwMgYIKwYBBQUH
AgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMCQGA1Ud
EQQdMBuBGXJ5YW4uaHVyc3RAZ2xvYmFsc2lnbi5jb20wCQYDVR0TBAIwADAdBgNV
HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9nc3BlcnNvbmFsc2lnbjJnMi5jcmww
VQYIKwYBBQUHAQEESTBHMEUGCCsGAQUFBzAChjlodHRwOi8vc2VjdXJlLmdsb2Jh
bHNpZ24uY29tL2NhY2VydC9nc3BlcnNvbmFsc2lnbjJnMi5jcnQwHQYDVR0OBBYE
FFWiECe0/L72eVYqcWYnLV6SSjzhMB8GA1UdIwQYMBaAFD8V0m18L+cxnkMKBqiU
bCw7xe5lMA0GCSqGSIb3DQEBBQUAA4IBAQAhQi6hLPeudmf3IBF4IDzCvRI0FaYd
BKfprSk/H0PDea4vpsLbWpA0t0SaijiJYtxKjlM4bPd+2chb7ejatDdyrZIzmDVy
q4c30/xMninGKokpYA11/Ve+i2dvjulu65qasrtQRGybAuuZ67lrp/K3OMFgjV5N
C3AHYLzvNU4Dwc4QQ1BaMOg6KzYSrKbABRZajfrpC9uiePsv7mDIXLx/toBPxWNl
a5vJm5DrZdn7uHdvBCE6kMykbOLN5pmEK0UIlwKh6Qi5XD0pzlVkEZliFkBMJgub
d/eF7xeg7TKPWC5xyOFp9SdMolJM7LTC3wnSO3frBAev+q/nGs9Xxyvs
-----END CERTIFICATE-----`

const smimeIntermediate = `-----BEGIN CERTIFICATE-----
MIIEFjCCAv6gAwIBAgILBAAAAAABL07hL1IwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0MTMxMDAw
MDBaFw0xOTA0MTMxMDAwMDBaMFQxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIFBlcnNvbmFsU2lnbiAy
IENBIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBa0H5Nez4
En3dIlFpX7e5E0YndxQ74xOBbz7kdBd+DLX0LOQMjVPU3DAgKL9ujhH+ZhHkURbH
3X/94TQSUL/z2JjsaQvS0NqyZXHhM5eeuquzOJRzEQ8+odETzHg2G0Erv7yjSeww
gkwDWDJnYUDlOjYTDUEG6+i+8Mn425reo4I0E277wD542kmVWeW7+oHv5dZo9e1Q
yWwiKTEP6BEQVVSBgThXMG4traSSDRUt3T1eQTZx5EObpiBEBO4OTqiBTJfg4vEI
YgkXzKLpnfszTB6YMDpR9/QS6p3ANB3kfAb+t6udSO3WCst0DGrwHDLBFGDR4UeY
T5KGGnI7cWL7AgMBAAGjgeUwgeIwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI
MAYBAf8CAQAwHQYDVR0OBBYEFD8V0m18L+cxnkMKBqiUbCw7xe5lMEcGA1UdIARA
MD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWdu
LmNvbS9yZXBvc2l0b3J5LzAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmds
b2JhbHNpZ24ubmV0L3Jvb3QuY3JsMB8GA1UdIwQYMBaAFGB7ZhpFDZfKiVAvfQTN
NKj//P1LMA0GCSqGSIb3DQEBBQUAA4IBAQBDc3nMpMxJMQMcYUCB3+C73UpvwDE8
eCOr7t2F/uaQKKcyqqstqLZc6vPwI/rcE9oDHugY5QEjQzIBIEaTnN6P0vege2IX
eCOr7t2F/uaQKKcyqqstqLZc6vPwI/rcE9oDHugY5QEjQzIBIEaTnN6P0vege2IX
YEvTWbWwGdPytDFPYIl3/6OqNSXSnZ7DxPcdLJq2uyiga8PB/TTIIHYkdM2+1DE0
7y3rH/7TjwDVD7SLu5/SdOfKskuMPTjOEvz3K161mymW06klVhubCIWOro/Gx1Q2
2FQOZ7/2k4uYoOdBTSlb8kTAuzZNgIE0rB2BIYCTz/P6zZIKW0ogbRSH
-----END CERTIFICATE-----`

var megaLeaf = `-----BEGIN CERTIFICATE-----
MIIFOjCCBCKgAwIBAgIQWYE8Dup170kZ+k11Lg51OjANBgkqhkiG9w0BAQUFADBy
MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEYMBYGA1UE
AxMPRXNzZW50aWFsU1NMIENBMB4XDTEyMTIxNDAwMDAwMFoXDTE0MTIxNDIzNTk1
OVowfzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMS4wLAYDVQQL
EyVIb3N0ZWQgYnkgSW5zdHJhIENvcnBvcmF0aW9uIFB0eS4gTFREMRUwEwYDVQQL
EwxFc3NlbnRpYWxTU0wxEzARBgNVBAMTCm1lZ2EuY28ubnowggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDcxMCClae8BQIaJHBUIVttlLvhbK4XhXPk3RQ3
G5XA6tLZMBQ33l3F9knYJ0YErXtr8IdfYoulRQFmKFMJl9GtWyg4cGQi2Rcr5VN5
S5dA1vu4oyJBxE9fPELcK6Yz1vqaf+n6za+mYTiQYKggVdS8/s8hmNuXP9Zk1pIn
+q0pGsf8NAcSHMJgLqPQrTDw+zae4V03DvcYfNKjuno88d2226ld7MAmQZ7uRNsI
/CnkdelVs+akZsXf0szefSqMJlf08SY32t2jj4Ra7RApVYxOftD9nij/aLfuqOU6
ow6IgIcIG2ZvXLZwK87c5fxL7UAsTTV+M1sVv8jA33V2oKLhAgMBAAGjggG9MIIB
uTAfBgNVHSMEGDAWgBTay+qtWwhdzP/8JlTOSeVVxjj0+DAdBgNVHQ4EFgQUmP9l
6zhyrZ06Qj4zogt+6LKFk4AwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAw
NAYDVR0lBC0wKwYIKwYBBQUHAwEGCCsGAQUFBwMCBgorBgEEAYI3CgMDBglghkgB
hvhCBAEwTwYDVR0gBEgwRjA6BgsrBgEEAbIxAQICBzArMCkGCCsGAQUFBwIBFh1o
dHRwczovL3NlY3VyZS5jb21vZG8uY29tL0NQUzAIBgZngQwBAgEwOwYDVR0fBDQw
MjAwoC6gLIYqaHR0cDovL2NybC5jb21vZG9jYS5jb20vRXNzZW50aWFsU1NMQ0Eu
Y3JsMG4GCCsGAQUFBwEBBGIwYDA4BggrBgEFBQcwAoYsaHR0cDovL2NydC5jb21v
ZG9jYS5jb20vRXNzZW50aWFsU1NMQ0FfMi5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6
Ly9vY3NwLmNvbW9kb2NhLmNvbTAlBgNVHREEHjAcggptZWdhLmNvLm56gg53d3cu
bWVnYS5jby5uejANBgkqhkiG9w0BAQUFAAOCAQEAcYhrsPSvDuwihMOh0ZmRpbOE
Gw6LqKgLNTmaYUPQhzi2cyIjhUhNvugXQQlP5f0lp5j8cixmArafg1dTn4kQGgD3
ivtuhBTgKO1VYB/VRoAt6Lmswg3YqyiS7JiLDZxjoV7KoS5xdiaINfHDUaBBY4ZH
j2BUlPniNBjCqXe/HndUTVUewlxbVps9FyCmH+C4o9DWzdGBzDpCkcmo5nM+cp7q
ZhTIFTvZfo3zGuBoyu8BzuopCJcFRm3cRiXkpI7iOMUIixO1szkJS6WpL1sKdT73
UXp08U0LBqoqG130FbzEJBBV3ixbvY6BWMHoCWuaoF12KJnC5kHt2RoWAAgMXA==
-----END CERTIFICATE-----`

var comodoIntermediate1 = `-----BEGIN CERTIFICATE-----
MIIFAzCCA+ugAwIBAgIQGLLLuqME8aAPwfLzJkYqSjANBgkqhkiG9w0BAQUFADCB
gTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNV
BAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjEyMDEwMDAw
MDBaFw0xOTEyMzEyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9E
TyBDQSBMaW1pdGVkMRgwFgYDVQQDEw9Fc3NlbnRpYWxTU0wgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt8AiwcsargxIxF3CJhakgEtSYau2A1NHf
5I5ZLdOWIY120j8YC0YZYwvHIPPlC92AGvFaoL0dds23Izp0XmEbdaqb1IX04XiR
0y3hr/yYLgbSeT1awB8hLRyuIVPGOqchfr7tZ291HRqfalsGs2rjsQuqag7nbWzD
ypWMN84hHzWQfdvaGlyoiBSyD8gSIF/F03/o4Tjg27z5H6Gq1huQByH6RSRQXScq
oChBRVt9vKCiL6qbfltTxfEFFld+Edc7tNkBdtzffRDPUanlOPJ7FAB1WfnwWdsX
Pvev5gItpHnBXaIcw5rIp6gLSApqLn8tl2X2xQScRMiZln5+pN0vAgMBAAGjggGD
MIIBfzAfBgNVHSMEGDAWgBQLWOWLxkwVN6RAqTCpIb5HNlpW/zAdBgNVHQ4EFgQU
2svqrVsIXcz//CZUzknlVcY49PgwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI
MAYBAf8CAQAwIAYDVR0lBBkwFwYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBMD4GA1Ud
IAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21v
ZG8uY29tL0NQUzBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLmNvbW9kb2Nh
LmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBsBggrBgEFBQcB
AQRgMF4wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NvbW9k
b1VUTlNHQ0NBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2Eu
Y29tMA0GCSqGSIb3DQEBBQUAA4IBAQAtlzR6QDLqcJcvgTtLeRJ3rvuq1xqo2l/z
odueTZbLN3qo6u6bldudu+Ennv1F7Q5Slqz0J790qpL0pcRDAB8OtXj5isWMcL2a
ejGjKdBZa0wztSz4iw+SY1dWrCRnilsvKcKxudokxeRiDn55w/65g+onO7wdQ7Vu
F6r7yJiIatnyfKH2cboZT7g440LX8NqxwCPf3dfxp+0Jj1agq8MLy6SSgIGSH6lv
+Wwz3D5XxqfyH8wqfOQsTEZf6/Nh9yvENZ+NWPU6g0QO2JOsTGvMd/QDzczc4BxL
XSXaPV7Od4rhPsbXlM1wSTz/Dr0ISKvlUhQVnQ6cGodWaK2cCQBk
-----END CERTIFICATE-----`

var comodoRoot = `-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIQToEtioJl4AsC7j41AkblPTANBgkqhkiG9w0BAQUFADCB
gTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNV
BAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjEyMDEwMDAw
MDBaFw0yOTEyMzEyMzU5NTlaMIGBMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01P
RE8gQ0EgTGltaXRlZDEnMCUGA1UEAxMeQ09NT0RPIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ECLi3LjkRv3
UcEbVASY06m/weaKXTuH+7uIzg3jLz8GlvCiKVCZrts7oVewdFFxze1CkU1B/qnI
2GqGd0S7WWaXUF601CxwRM/aN5VCaTwwxHGzUvAhTaHYujl8HJ6jJJ3ygxaYqhZ8
Q5sVW7euNJH+1GImGEaaP+vB+fGQV+useg2L23IwambV4EajcNxo2f8ESIl33rXp
+2dtQem8Ob0y2WIC8bGoPW43nOIv4tOiJovGuFVDiOEjPqXSJDlqR6sA1KGzqSX+
DT+nHbrTUcELpNqsOO9VUCQFZUaTNE8tja3G1CEZ0o7KBWFxB3NH5YoZEr0ETc5O
nKVIrLsm9wIDAQABo4GOMIGLMB0GA1UdDgQWBBQLWOWLxkwVN6RAqTCpIb5HNlpW
/zAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBJBgNVHR8EQjBAMD6g
PKA6hjhodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9u
QXV0aG9yaXR5LmNybDANBgkqhkiG9w0BAQUFAAOCAQEAPpiem/Yb6dc5t3iuHXIY
SdOH5EOC6z/JqvWote9VfCFSZfnVDeFs9D6Mk3ORLgLETgdxb8CPOGEIqB6BCsAv
IC9Bi5HcSEW88cbeunZrM8gALTFGTO3nnc+IlP8zwFboJIYmuNg4ON8qa90SzMc/
RxdMosIGlgnW2/4/PEZB31jiVg88O8EckzXZOFKs7sjsLjBOlDW0JB9LeGna8gI4
zJVSk/BwJVmcIGfE7vmLV2H0knZ9P4SNVbfo5azV8fUZVqZa+5Acr5Pr5RzUZ5dd
BA6+C4OmF4O5MBKgxTMVBbkN+8cFduPYSo38NBejxiEovjBFMR7HeL5YYTisO+IB
ZQ==
-----END CERTIFICATE-----`

var nameConstraintsLeaf = `-----BEGIN CERTIFICATE-----
MIIHMTCCBRmgAwIBAgIIIZaV/3ezOJkwDQYJKoZIhvcNAQEFBQAwgcsxCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEj
MCEGA1UECxMaR2xvYmFsIFF1YWxpZmllZCBTZXJ2ZXIgQ0ExPDA6BgNVBAoTM1Zp
cmdpbmlhIFBvbHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUgVW5pdmVyc2l0
eTExMC8GA1UEAxMoVmlyZ2luaWEgVGVjaCBHbG9iYWwgUXVhbGlmaWVkIFNlcnZl
ciBDQTAeFw0xMzA5MTkxNDM2NTVaFw0xNTA5MTkxNDM2NTVaMIHNMQswCQYDVQQG
EwJVUzERMA8GA1UECAwIVmlyZ2luaWExEzARBgNVBAcMCkJsYWNrc2J1cmcxPDA6
BgNVBAoMM1ZpcmdpbmlhIFBvbHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUg
VW5pdmVyc2l0eTE7MDkGA1UECwwyVGVjaG5vbG9neS1lbmhhbmNlZCBMZWFybmlu
ZyBhbmQgT25saW5lIFN0cmF0ZWdpZXMxGzAZBgNVBAMMEnNlY3VyZS5pZGRsLnZ0
LmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkOyPpsOK/6IuPG
WnIBlVwlHzeYf+cUlggqkLq0b0+vZbiTXgio9/VCuNQ8opSoss7J7o3ygV9to+9Y
YwJKVC5WDT/y5JWpQey0CWILymViJnpNSwnxBc8A+Q8w5NUGDd/UhtPx/U8/hqbd
WPDYj2hbOqyq8UlRhfS5pwtnv6BbCTaY11I6FhCLK7zttISyTuWCf9p9o/ggiipP
ii/5oh4dkl+r5SfuSp5GPNHlYO8lWqys5NAPoDD4fc/kuflcK7Exx7XJ+Oqu0W0/
psjEY/tES1ZgDWU/ParcxxFpFmKHbD5DXsfPOObzkVWXIY6tGMutSlE1Froy/Nn0
OZsAOrcCAwEAAaOCAhMwggIPMIG4BggrBgEFBQcBAQSBqzCBqDBYBggrBgEFBQcw
AoZMaHR0cDovL3d3dy5wa2kudnQuZWR1L2dsb2JhbHF1YWxpZmllZHNlcnZlci9j
YWNlcnQvZ2xvYmFscXVhbGlmaWVkc2VydmVyLmNydDBMBggrBgEFBQcwAYZAaHR0
cDovL3Z0Y2EtcC5lcHJvdi5zZXRpLnZ0LmVkdTo4MDgwL2VqYmNhL3B1YmxpY3dl
Yi9zdGF0dXMvb2NzcDAdBgNVHQ4EFgQUp7xbO6iHkvtZbPE4jmndmnAbSEcwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBS8YmAn1eM1SBfpS6tFatDIqHdxjDBqBgNV
HSAEYzBhMA4GDCsGAQQBtGgFAgICATAOBgwrBgEEAbRoBQICAQEwPwYMKwYBBAG0
aAUCAgMBMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9i
YWwvY3BzLzBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vd3d3LnBraS52dC5lZHUv
Z2xvYmFscXVhbGlmaWVkc2VydmVyL2NybC9jYWNybC5jcmwwDgYDVR0PAQH/BAQD
AgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUghJz
ZWN1cmUuaWRkbC52dC5lZHUwDQYJKoZIhvcNAQEFBQADggIBAEgoYo4aUtatY3gI
OyyKp7QlIOaLbTJZywESHqy+L5EGDdJW2DJV+mcE0LDGvqa2/1Lo+AR1ntsZwfOi
Y718JwgVVaX/RCd5+QKP25c5/x72xI8hb/L1bgS0ED9b0YAhd7Qm1K1ot82+6mqX
DW6WiGeDr8Z07MQ3143qQe2rBlq+QI69DYzm2GOqAIAnUIWv7tCyLUm31b4DwmrJ
TeudVreTKUbBNB1TWRFHEPkWhjjXKZnNGRO11wHXcyBu6YekIvVZ+vmx8ePee4jJ
3GFOi7lMuWOeq57jTVL7KOKaKLVXBb6gqo5aq+Wwt8RUD5MakrCAEeQZj7DKaFmZ
oQCO0Pxrsl3InCGvxnGzT+bFVO9nJ/BAMj7hknFdm9Jr6Bg5q33Z+gnf909AD9QF
ESqUSykaHu2LVdJx2MaCH1CyKnRgMw5tEwE15EXpUjCm24m8FMOYC+rNtf18pgrz
5D8Jhh+oxK9PjcBYqXNtnioIxiMCYcV0q5d4w4BYFEh71tk7/bYB0R55CsBUVPmp
timWNOdRd57Tfpk3USaVsumWZAf9MP3wPiC7gb4d5tYEEAG5BuDT8ruFw838wU8G
1VvAVutSiYBg7k3NYO7AUqZ+Ax4klQX3aM9lgonmJ78Qt94UPtbptrfZ4/lSqEf8
GBUwDrQNTb+gsXsDkjd5lcYxNx6l
-----END CERTIFICATE-----`

var nameConstraintsIntermediate1 = `-----BEGIN CERTIFICATE-----
MIINLjCCDBagAwIBAgIRIqpyf/YoGgvHc8HiDAxAI8owDQYJKoZIhvcNAQEFBQAw
XDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4X
DTEyMTIxMzAwMDAwMFoXDTE3MTIxMzAwMDAwMFowgcsxCzAJBgNVBAYTAlVTMREw
DwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEjMCEGA1UECxMa
R2xvYmFsIFF1YWxpZmllZCBTZXJ2ZXIgQ0ExPDA6BgNVBAoTM1ZpcmdpbmlhIFBv
bHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUgVW5pdmVyc2l0eTExMC8GA1UE
AxMoVmlyZ2luaWEgVGVjaCBHbG9iYWwgUXVhbGlmaWVkIFNlcnZlciBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALgIZhEaptBWADBqdJ45ueFGzMXa
GHnzNxoxR1fQIaaRQNdCg4cw3A4dWKMeEgYLtsp65ai3Xfw62Qaus0+KJ3RhgV+r
ihqK81NUzkls78fJlADVDI4fCTlothsrE1CTOMiy97jKHai5mVTiWxmcxpmjv7fm
5Nhc+uHgh2hIz6npryq495mD51ZrUTIaqAQN6Pw/VHfAmR524vgriTOjtp1t4lA9
pXGWjF/vkhAKFFheOQSQ00rngo2wHgCqMla64UTN0oz70AsCYNZ3jDLx0kOP0YmM
R3Ih91VA63kLqPXA0R6yxmmhhxLZ5bcyAy1SLjr1N302MIxLM/pSy6aquEnbELhz
qyp9yGgRyGJay96QH7c4RJY6gtcoPDbldDcHI9nXngdAL4DrZkJ9OkDkJLyqG66W
ZTF5q4EIs6yMdrywz0x7QP+OXPJrjYpbeFs6tGZCFnWPFfmHCRJF8/unofYrheq+
9J7Jx3U55S/k57NXbAM1RAJOuMTlfn9Etf9Dpoac9poI4Liav6rBoUQk3N3JWqnV
HNx/NdCyJ1/6UbKMJUZsStAVglsi6lVPo289HHOE4f7iwl3SyekizVOp01wUin3y
cnbZB/rXmZbwapSxTTSBf0EIOr9i4EGfnnhCAVA9U5uLrI5OEB69IY8PNX0071s3
Z2a2fio5c8m3JkdrAgMBAAGjggh5MIIIdTAOBgNVHQ8BAf8EBAMCAQYwTAYDVR0g
BEUwQzBBBgkrBgEEAaAyATwwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xv
YmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wEgYDVR0TAQH/BAgwBgEB/wIBADCCBtAG
A1UdHgSCBscwggbDoIIGvzASghAzZGJsYWNrc2J1cmcub3JnMBiCFmFjY2VsZXJh
dGV2aXJnaW5pYS5jb20wGIIWYWNjZWxlcmF0ZXZpcmdpbmlhLm9yZzALgglhY3Zj
cC5vcmcwCYIHYmV2Lm5ldDAJggdiZXYub3JnMAuCCWNsaWdzLm9yZzAMggpjbWl3
ZWIub3JnMBeCFWVhc3Rlcm5icm9va3Ryb3V0Lm5ldDAXghVlYXN0ZXJuYnJvb2t0
cm91dC5vcmcwEYIPZWNvcnJpZG9ycy5pbmZvMBOCEWVkZ2FycmVzZWFyY2gub3Jn
MBKCEGdldC1lZHVjYXRlZC5jb20wE4IRZ2V0LWVkdWNhdGVkLmluZm8wEYIPZ2V0
ZWR1Y2F0ZWQubmV0MBKCEGdldC1lZHVjYXRlZC5uZXQwEYIPZ2V0ZWR1Y2F0ZWQu
b3JnMBKCEGdldC1lZHVjYXRlZC5vcmcwD4INaG9raWVjbHViLmNvbTAQgg5ob2tp
ZXBob3RvLmNvbTAPgg1ob2tpZXNob3AuY29tMBGCD2hva2llc3BvcnRzLmNvbTAS
ghBob2tpZXRpY2tldHMuY29tMBKCEGhvdGVscm9hbm9rZS5jb20wE4IRaHVtYW53
aWxkbGlmZS5vcmcwF4IVaW5uYXR2aXJnaW5pYXRlY2guY29tMA+CDWlzY2hwMjAx
MS5vcmcwD4INbGFuZHJlaGFiLm9yZzAggh5uYXRpb25hbHRpcmVyZXNlYXJjaGNl
bnRlci5jb20wFYITbmV0d29ya3ZpcmdpbmlhLm5ldDAMggpwZHJjdnQuY29tMBiC
FnBldGVkeWVyaXZlcmNvdXJzZS5jb20wDYILcmFkaW9pcS5vcmcwFYITcml2ZXJj
b3Vyc2Vnb2xmLmNvbTALgglzZGltaS5vcmcwEIIOc292YW1vdGlvbi5jb20wHoIc
c3VzdGFpbmFibGUtYmlvbWF0ZXJpYWxzLmNvbTAeghxzdXN0YWluYWJsZS1iaW9t
YXRlcmlhbHMub3JnMBWCE3RoaXNpc3RoZWZ1dHVyZS5jb20wGIIWdGhpcy1pcy10
aGUtZnV0dXJlLmNvbTAVghN0aGlzaXN0aGVmdXR1cmUubmV0MBiCFnRoaXMtaXMt
dGhlLWZ1dHVyZS5uZXQwCoIIdmFkcy5vcmcwDIIKdmFsZWFmLm9yZzANggt2YXRl
Y2guaW5mbzANggt2YXRlY2gubW9iaTAcghp2YXRlY2hsaWZlbG9uZ2xlYXJuaW5n
LmNvbTAcghp2YXRlY2hsaWZlbG9uZ2xlYXJuaW5nLm5ldDAcghp2YXRlY2hsaWZl
bG9uZ2xlYXJuaW5nLm9yZzAKggh2Y29tLmVkdTASghB2aXJnaW5pYXZpZXcubmV0
MDSCMnZpcmdpbmlhcG9seXRlY2huaWNpbnN0aXR1dGVhbmRzdGF0ZXVuaXZlcnNp
dHkuY29tMDWCM3ZpcmdpbmlhcG9seXRlY2huaWNpbnN0aXR1dGVhbmRzdGF0ZXVu
aXZlcnNpdHkuaW5mbzA0gjJ2aXJnaW5pYXBvbHl0ZWNobmljaW5zdGl0dXRlYW5k
c3RhdGV1bml2ZXJzaXR5Lm5ldDA0gjJ2aXJnaW5pYXBvbHl0ZWNobmljaW5zdGl0
dXRlYW5kc3RhdGV1bml2ZXJzaXR5Lm9yZzAZghd2aXJnaW5pYXB1YmxpY3JhZGlv
Lm9yZzASghB2aXJnaW5pYXRlY2guZWR1MBOCEXZpcmdpbmlhdGVjaC5tb2JpMByC
GnZpcmdpbmlhdGVjaGZvdW5kYXRpb24ub3JnMAiCBnZ0LmVkdTALggl2dGFyYy5v
cmcwDIIKdnQtYXJjLm9yZzALggl2dGNyYy5jb20wCoIIdnRpcC5vcmcwDIIKdnRs
ZWFuLm9yZzAWghR2dGtub3dsZWRnZXdvcmtzLmNvbTAYghZ2dGxpZmVsb25nbGVh
cm5pbmcuY29tMBiCFnZ0bGlmZWxvbmdsZWFybmluZy5uZXQwGIIWdnRsaWZlbG9u
Z2xlYXJuaW5nLm9yZzATghF2dHNwb3J0c21lZGlhLmNvbTALggl2dHdlaS5jb20w
D4INd2l3YXR3ZXJjLmNvbTAKggh3dnRmLm9yZzAIgQZ2dC5lZHUwd6R1MHMxCzAJ
BgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVy
ZzE8MDoGA1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFuZCBT
dGF0ZSBVbml2ZXJzaXR5MCcGA1UdJQQgMB4GCCsGAQUFBwMCBggrBgEFBQcDAQYI
KwYBBQUHAwkwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5nbG9iYWxzaWdu
LmNvbS9ncy90cnVzdHJvb3RnMi5jcmwwgYQGCCsGAQUFBwEBBHgwdjAzBggrBgEF
BQcwAYYnaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3RydXN0cm9vdGcyMD8G
CCsGAQUFBzAChjNodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90
cnVzdHJvb3RnMi5jcnQwHQYDVR0OBBYEFLxiYCfV4zVIF+lLq0Vq0Miod3GMMB8G
A1UdIwQYMBaAFBT25YsxtkWASkxt/MKHico2w5BiMA0GCSqGSIb3DQEBBQUAA4IB
AQAyJm/lOB2Er4tHXhc/+fSufSzgjohJgYfMkvG4LknkvnZ1BjliefR8tTXX49d2
SCDFWfGjqyJZwavavkl/4p3oXPG/nAMDMvxh4YAT+CfEK9HH+6ICV087kD4BLegi
+aFJMj8MMdReWCzn5sLnSR1rdse2mo2arX3Uod14SW+PGrbUmTuWNyvRbz3fVmxp
UdbGmj3laknO9YPsBGgHfv73pVVsTJkW4ZfY/7KdD/yaVv6ophpOB3coXfjl2+kd
Z4ypn2zK+cx9IL/LSewqd/7W9cD55PCUy4X9OTbEmAccwiz3LB66mQoUGfdHdkoB
jUY+v9vLQXmaVwI0AYL7g9LN
-----END CERTIFICATE-----`

var nameConstraintsIntermediate2 = `-----BEGIN CERTIFICATE-----
MIIEXTCCA0WgAwIBAgILBAAAAAABNuk6OrMwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMjA0MjUxMTAw
MDBaFw0yNzA0MjUxMTAwMDBaMFwxCzAJBgNVBAYTAkJFMRUwEwYDVQQLEwxUcnVz
dGVkIFJvb3QxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGzAZBgNVBAMTElRy
dXN0ZWQgUm9vdCBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKyuvqrtcMr7g7EuNbu4sKwxM127UsCmx1RxbxxgcArGS7rjiefpBH/w4LYrymjf
vcw1ueyMNoqLo9nJMz/ORXupb35NNfE667prQYHa+tTjl1IiKpB7QUwt3wXPuTMF
Ja1tXtjKzkqJyuJlNuPKT76HcjgNqgV1s9qG44MD5I2JvI12du8zI1bgdQ+l/KsX
kTfbGjUvhOLOlVNWVQDpL+YMIrGqgBYxy5TUNgrAcRtwpNdS2KkF5otSmMweVb5k
hoUVv3u8UxQH/WWbNhHq1RrIlg/0rBUfi/ziShYFSB7U+aLx5DxPphTFBiDquQGp
tB+FC4JvnukDStFihZCZ1R8CAwEAAaOCASMwggEfMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAdBgNVHQ4E
FgQUFPblizG2RYBKTG38woeJyjbDkGIwMwYDVR0fBCwwKjAooCagJIYiaHR0cDov
L2NybC5nbG9iYWxzaWduLm5ldC9yb290LmNybDA+BggrBgEFBQcBAQQyMDAwLgYI
KwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjEwHwYD
VR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEB
AL7IG0l+k4LkcpI+a/kvZsSRwSM4uA6zGX34e78A2oytr8RG8bJwVb8+AHMUD+Xe
2kYdh/Uj/waQXfqR0OgxQXL9Ct4ZM+JlR1avsNKXWL5AwYXAXCOB3J5PW2XOck7H
Zw0vRbGQhjWjQx+B4KOUFg1b3ov/z6Xkr3yaCfRQhXh7KC0Bc0RXPPG5Nv5lCW+z
tbbg0zMm3kyfQITRusMSg6IBsDJqOnjaiaKQRcXiD0Sk43ZXb2bUKMxC7+Td3QL4
RyHcWJbQ7YylLTS/x+jxWIcOQ0oO5/54t5PTQ14neYhOz9x4gUk2AYAW6d1vePwb
hcC8roQwkHT7HvfYBoc74FM=
-----END CERTIFICATE-----`

var globalSignRoot = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----`

var moipLeafCert = `-----BEGIN CERTIFICATE-----
MIIGQDCCBSigAwIBAgIRAPe/cwh7CUWizo8mYSDavLIwDQYJKoZIhvcNAQELBQAw
gZIxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYD
VQQDEy9DT01PRE8gUlNBIEV4dGVuZGVkIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZl
ciBDQTAeFw0xMzA4MTUwMDAwMDBaFw0xNDA4MTUyMzU5NTlaMIIBQjEXMBUGA1UE
BRMOMDg3MTg0MzEwMDAxMDgxEzARBgsrBgEEAYI3PAIBAxMCQlIxGjAYBgsrBgEE
AYI3PAIBAhMJU2FvIFBhdWxvMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlv
bjELMAkGA1UEBhMCQlIxETAPBgNVBBETCDAxNDUyMDAwMRIwEAYDVQQIEwlTYW8g
UGF1bG8xEjAQBgNVBAcTCVNhbyBQYXVsbzEtMCsGA1UECRMkQXZlbmlkYSBCcmln
YWRlaXJvIEZhcmlhIExpbWEgLCAyOTI3MR0wGwYDVQQKExRNb2lwIFBhZ2FtZW50
b3MgUy5BLjENMAsGA1UECxMETU9JUDEYMBYGA1UECxMPU1NMIEJsaW5kYWRvIEVW
MRgwFgYDVQQDEw9hcGkubW9pcC5jb20uYnIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN0b9x6TrXXA9hPCF8/NjqGJ++2D4LO4ZiMFTjs0VwpXy2Y1Oe
s74/HuiLGnAHxTmAtV7IpZMibiOcTxcnDYp9oEWkf+gR+hZvwFZwyOBC7wyb3SR3
UvV0N1ZbEVRYpN9kuX/3vjDghjDmzzBwu8a/T+y5JTym5uiJlngVAWyh/RjtIvYi
+NVkQMbyVlPGkoCe6c30pH8DKYuUCZU6DHjUsPTX3jAskqbhDSAnclX9iX0p2bmw
KVBc+5Vh/2geyzDuquF0w+mNIYdU5h7uXvlmJnf3d2Cext5dxdL8/jezD3U0dAqI
pYSKERbyxSkJWxdvRlhdpM9YXMJcpc88xNp1AgMBAAGjggHcMIIB2DAfBgNVHSME
GDAWgBQ52v/KKBSKqHQTCLnkDqnS+n6daTAdBgNVHQ4EFgQU/lXuOa7DMExzZjRj
LQWcMWGZY7swDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMEYGA1UdIAQ/MD0wOwYMKwYBBAGyMQECAQUB
MCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5jb20vQ1BTMFYG
A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9ET1JT
QUV4dGVuZGVkVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNybDCBhwYIKwYBBQUH
AQEEezB5MFEGCCsGAQUFBzAChkVodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01P
RE9SU0FFeHRlbmRlZFZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAvBgNVHREEKDAmgg9hcGku
bW9pcC5jb20uYnKCE3d3dy5hcGkubW9pcC5jb20uYnIwDQYJKoZIhvcNAQELBQAD
ggEBAFoTmPlaDcf+nudhjXHwud8g7/LRyA8ucb+3/vfmgbn7FUc1eprF5sJS1mA+
pbiTyXw4IxcJq2KUj0Nw3IPOe9k84mzh+XMmdCKH+QK3NWkE9Udz+VpBOBc0dlqC
1RH5umStYDmuZg/8/r652eeQ5kUDcJyADfpKWBgDPYaGtwzKVT4h3Aok9SLXRHx6
z/gOaMjEDMarMCMw4VUIG1pvNraZrG5oTaALPaIXXpd8VqbQYPudYJ6fR5eY3FeW
H/ofbYFdRcuD26MfBFWE9VGGral9Fgo8sEHffho+UWhgApuQV4/l5fMzxB5YBXyQ
jhuy8PqqZS9OuLilTeLu4a8z2JI=
-----END CERTIFICATE-----`

var comodoIntermediateSHA384 = `-----BEGIN CERTIFICATE-----
MIIGDjCCA/agAwIBAgIQBqdDgNTr/tQ1taP34Wq92DANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTIwMjEy
MDAwMDAwWhcNMjcwMjExMjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBSU0EgRXh0ZW5kZWQg
VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAlVbeVLTf1QJJe9FbXKKyHo+cK2JMK40SKPMalaPGEP0p3uGf
CzhAk9HvbpUQ/OGQF3cs7nU+e2PsYZJuTzurgElr3wDqAwB/L3XVKC/sVmePgIOj
vdwDmZOLlJFWW6G4ajo/Br0OksxgnP214J9mMF/b5pTwlWqvyIqvgNnmiDkBfBzA
xSr3e5Wg8narbZtyOTDr0VdVAZ1YEZ18bYSPSeidCfw8/QpKdhQhXBZzQCMZdMO6
WAqmli7eNuWf0MLw4eDBYuPCGEUZUaoXHugjddTI0JYT/8ck0YwLJ66eetw6YWNg
iJctXQUL5Tvrrs46R3N2qPos3cCHF+msMJn4HwIDAQABo4IBaTCCAWUwHwYDVR0j
BBgwFoAUu69+Aj36pvE8hI6t7jiY7NkyMtQwHQYDVR0OBBYEFDna/8ooFIqodBMI
ueQOqdL6fp1pMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMD4G
A1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5j
b21vZG8uY29tL0NQUzBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9k
b2NhLmNvbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggr
BgEFBQcBAQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29t
L0NPTU9ET1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
cC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAERCnUFRK0iIXZebeV4R
AUpSGXtBLMeJPNBy3IX6WK/VJeQT+FhlZ58N/1eLqYVeyqZLsKeyLeCMIs37/3mk
jCuN/gI9JN6pXV/kD0fQ22YlPodHDK4ixVAihNftSlka9pOlk7DgG4HyVsTIEFPk
1Hax0VtpS3ey4E/EhOfUoFDuPPpE/NBXueEoU/1Tzdy5H3pAvTA/2GzS8+cHnx8i
teoiccsq8FZ8/qyo0QYPFBRSTP5kKwxpKrgNUG4+BAe/eiCL+O5lCeHHSQgyPQ0o
fkkdt0rvAucNgBfIXOBhYsvss2B5JdoaZXOcOBCgJjqwyBZ9kzEi7nQLiMBciUEA
KKlHMd99SUWa9eanRRrSjhMQ34Ovmw2tfn6dNVA0BM7pINae253UqNpktNEvWS5e
ojZh1CSggjMziqHRbO9haKPl0latxf1eYusVqHQSTC8xjOnB3xBLAer2VBvNfzu9
XJ/B288ByvK6YBIhMe2pZLiySVgXbVrXzYxtvp5/4gJYp9vDLVj2dAZqmvZh+fYA
tmnYOosxWd2R5nwnI4fdAw+PKowegwFOAWEMUnNt/AiiuSpm5HZNMaBWm9lTjaK2
jwLI5jqmBNFI+8NKAnb9L9K8E7bobTQk+p0pisehKxTxlgBzuRPpwLk6R1YCcYAn
pLwltum95OmYdBbxN4SBB7SC
-----END CERTIFICATE-----`

const comodoRSAAuthority = `-----BEGIN CERTIFICATE-----
MIIFdDCCBFygAwIBAgIQJ2buVutJ846r13Ci/ITeIjANBgkqhkiG9w0BAQwFADBv
MQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk
ZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF
eHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow
gYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD
VQQDEyJDT01PRE8gUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkehUktIKVrGsDSTdxc9EZ3SZKzejfSNw
AHG8U9/E+ioSj0t/EFa9n3Byt2F/yUsPF6c947AEYe7/EZfH9IY+Cvo+XPmT5jR6
2RRr55yzhaCCenavcZDX7P0N+pxs+t+wgvQUfvm+xKYvT3+Zf7X8Z0NyvQwA1onr
ayzT7Y+YHBSrfuXjbvzYqOSSJNpDa2K4Vf3qwbxstovzDo2a5JtsaZn4eEgwRdWt
4Q08RWD8MpZRJ7xnw8outmvqRsfHIKCxH2XeSAi6pE6p8oNGN4Tr6MyBSENnTnIq
m1y9TBsoilwie7SrmNnu4FGDwwlGTm0+mfqVF9p8M1dBPI1R7Qu2XK8sYxrfV8g/
vOldxJuvRZnio1oktLqpVj3Pb6r/SVi+8Kj/9Lit6Tf7urj0Czr56ENCHonYhMsT
8dm74YlguIwoVqwUHZwK53Hrzw7dPamWoUi9PPevtQ0iTMARgexWO/bTouJbt7IE
IlKVgJNp6I5MZfGRAy1wdALqi2cVKWlSArvX31BqVUa/oKMoYX9w0MOiqiwhqkfO
KJwGRXa/ghgntNWutMtQ5mv0TIZxMOmm3xaG4Nj/QN370EKIf6MzOi5cHkERgWPO
GHFrK+ymircxXDpqR+DDeVnWIBqv8mqYqnK8V0rSS527EPywTEHl7R09XiidnMy/
s1Hap0flhFMCAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rEJlTvA73g
JMtUGjAdBgNVHQ4EFgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQD
AgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQGA1UdHwQ9
MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVzdEV4dGVy
bmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6
Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggEBAGS/g/FfmoXQ
zbihKVcN6Fr30ek+8nYEbvFScLsePP9NDXRqzIGCJdPDoCpdTPW6i6FtxFQJdcfj
Jw5dhHk3QBN39bSsHNA7qxcS1u80GH4r6XnTq1dFDK8o+tDb5VCViLvfhVdpfZLY
Uspzgb8c8+a4bmYRBbMelC1/kZWSWfFMzqORcUx8Rww7Cxn2obFshj5cqsQugsv5
B5a6SE2Q8pTIqXOi6wZ7I53eovNNVZ96YUWYGGjHXkBrI/V5eu+MtWuLt29G9Hvx
PUsE2JOAWVrgQSQdso8VYFhH2+9uRv0V9dlfmrPb2LjkQLPNlzmuhbsdjrzch5vR
pu/xO28QOG8=
-----END CERTIFICATE-----`

const addTrustRoot = `-----BEGIN CERTIFICATE-----
MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU
MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs
IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290
MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux
FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h
bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt
H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9
uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX
mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX
a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN
E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0
WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD
VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0
Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU
cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN
AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH
YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5
6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC
Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX
c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a
mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=
-----END CERTIFICATE-----`

const zcryptoRoot = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ZCrypto Root Authority
        Validity
            Not Before: Jan  1 00:00:00 2017 GMT
            Not After : Jan  1 00:00:00 2027 GMT
        Subject: CN=ZCrypto Root Authority
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:cc:21:ee:62:89:e6:94:f4:65:4b:50:17:5d:61:
                    29:7b:2e:cc:d2:14:ca:7d:19:d6:94:08:2a:45:61:
                    87:4a:87:8a:a5:ee:b6:d8:71:68:fe:31:80:8f:13:
                    8a:17:be:16:6b:10:f0:eb:38:7a:d3:37:2c:e2:c8:
                    e9:f4:10:97:53:b1:84:c7:2e:cd:46:98:a7:59:1f:
                    80:53:06:cd:e4:8a:0f:5e:9a:17:13:34:04:96:68:
                    54:e9:44:06:5f:59:9c:c7:9b:28:a9:fe:35:e6:41:
                    61:0c:fc:06:3c:b4:b8:b3:a6:3e:ec:92:39:01:ab:
                    de:73:64:0c:65:1d:6c:0f:ce:f2:31:32:69:49:e3:
                    8a:62:02:95:63:de:17:2b:db:a4:18:04:5a:f6:d7:
                    66:7f:4e:b7:c4:df:84:49:ef:fb:4c:56:87:4b:02:
                    08:3d:57:8f:54:6b:dc:68:1f:ef:ba:ac:8b:b1:1e:
                    e7:74:f7:55:ec:76:bf:cc:fb:e9:25:6d:e6:c5:f4:
                    13:08:2b:b6:0e:27:dc:3c:81:18:c2:18:ea:a9:df:
                    6d:6f:6b:0c:df:ef:ee:c8:f0:af:fc:08:61:db:5c:
                    88:cc:82:af:e6:a5:d1:4d:6e:d5:b3:1a:a3:49:aa:
                    3d:bb:d6:9b:8b:b2:b6:61:0f:fb:0b:1b:56:e1:17:
                    8f:f7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                C6:BA:1E:48:92:8B:43:54:07:74:80:79:16:92:55:CA:EC:7D:D0:35
            X509v3 Authority Key Identifier:
                keyid:C6:BA:1E:48:92:8B:43:54:07:74:80:79:16:92:55:CA:EC:7D:D0:35

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
    Signature Algorithm: sha256WithRSAEncryption
        b5:c6:05:f7:06:34:4e:ba:cb:a1:5e:ec:d9:14:03:e1:d4:8e:
        e9:ea:21:db:16:18:dd:99:96:62:26:40:11:e1:79:7c:98:df:
        1b:1f:b5:90:db:50:ce:7d:b1:df:c9:5d:75:bc:f7:7c:3b:2c:
        5b:fb:cf:14:61:64:f5:b7:8d:d7:29:da:4c:6e:7c:30:fb:c5:
        79:e0:84:e8:9c:96:f6:a9:c9:4c:df:41:29:f0:80:21:77:8d:
        20:e6:50:b8:f8:8d:9b:19:65:d4:2f:c7:99:33:46:41:11:30:
        40:ee:e3:bc:9d:4e:aa:84:51:cc:89:e2:c7:44:83:24:b6:b8:
        b7:67:20:90:1a:6f:9b:3c:1f:c5:78:49:4f:80:01:c2:31:6b:
        50:7b:27:49:95:d3:61:5f:59:93:bb:b6:cd:76:f6:ab:1b:76:
        0b:b3:7a:7a:3c:ae:cb:33:ff:3d:5b:0f:f2:ab:51:f5:73:c5:
        ad:d5:c3:9c:e1:c7:d5:e8:1c:3d:cb:87:d8:2c:24:76:fe:e6:
        f7:fe:ee:2a:45:24:15:ce:c1:09:94:8c:27:07:b4:40:0f:c6:
        0b:a3:ce:44:13:0c:28:09:8d:b1:32:25:26:51:3d:cd:41:0f:
        ad:38:f7:a7:81:42:ce:5c:04:fc:fd:81:c6:c5:60:1b:0d:65:
        c3:a4:62:dd
-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIBADANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZaQ3J5
cHRvIFJvb3QgQXV0aG9yaXR5MB4XDTE3MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAw
MFowITEfMB0GA1UEAwwWWkNyeXB0byBSb290IEF1dGhvcml0eTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwh7mKJ5pT0ZUtQF11hKXsuzNIUyn0Z1pQI
KkVhh0qHiqXutthxaP4xgI8Tihe+FmsQ8Os4etM3LOLI6fQQl1OxhMcuzUaYp1kf
gFMGzeSKD16aFxM0BJZoVOlEBl9ZnMebKKn+NeZBYQz8Bjy0uLOmPuySOQGr3nNk
DGUdbA/O8jEyaUnjimIClWPeFyvbpBgEWvbXZn9Ot8TfhEnv+0xWh0sCCD1Xj1Rr
3Ggf77qsi7Ee53T3Vex2v8z76SVt5sX0Ewgrtg4n3DyBGMIY6qnfbW9rDN/v7sjw
r/wIYdtciMyCr+al0U1u1bMao0mqPbvWm4uytmEP+wsbVuEXj/cCAwEAAaNjMGEw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxroeSJKLQ1QHdIB5FpJVyux90DUw
HwYDVR0jBBgwFoAUxroeSJKLQ1QHdIB5FpJVyux90DUwDgYDVR0PAQH/BAQDAgEG
MA0GCSqGSIb3DQEBCwUAA4IBAQC1xgX3BjROusuhXuzZFAPh1I7p6iHbFhjdmZZi
JkAR4Xl8mN8bH7WQ21DOfbHfyV11vPd8Oyxb+88UYWT1t43XKdpMbnww+8V54ITo
nJb2qclM30Ep8IAhd40g5lC4+I2bGWXUL8eZM0ZBETBA7uO8nU6qhFHMieLHRIMk
tri3ZyCQGm+bPB/FeElPgAHCMWtQeydJldNhX1mTu7bNdvarG3YLs3p6PK7LM/89
Ww/yq1H1c8Wt1cOc4cfV6Bw9y4fYLCR2/ub3/u4qRSQVzsEJlIwnB7RAD8YLo85E
EwwoCY2xMiUmUT3NQQ+tOPengULOXAT8/YHGxWAbDWXDpGLd
-----END CERTIFICATE-----
`
const zcryptoIntermediate = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ZCrypto Root Authority
        Validity
            Not Before: Jan  1 00:00:00 2020 GMT
            Not After : Dec 31 00:00:00 2026 GMT
        Subject: CN=ZCrypto Root Authority
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:cc:5c:8e:fd:d1:09:44:e5:a6:57:96:b1:c7:13:
                    36:b8:5f:c7:5c:b1:2a:0f:8f:6e:5a:f4:f3:38:d9:
                    18:57:08:3d:5e:87:fa:ba:09:4c:36:14:40:32:4c:
                    ff:46:c7:17:f6:dd:3f:02:8e:da:4f:5b:3d:96:01:
                    65:58:32:c6:4c:b2:bd:65:c7:92:b2:20:2b:23:1d:
                    ef:c5:07:75:4c:f5:52:6d:6d:5c:1a:18:e7:88:f8:
                    e7:76:51:e6:48:61:5a:d9:94:c5:6c:c0:41:22:f2:
                    a6:47:aa:e9:fc:bf:a4:d3:30:24:c9:86:c3:d5:24:
                    3e:9c:38:db:10:e5:7b:71:dc:15:a1:a8:48:05:6d:
                    fc:32:19:0f:cc:28:75:75:1f:5d:2b:98:de:b8:0c:
                    2e:b5:f4:4b:bf:71:13:be:3e:9c:32:d2:4f:17:3d:
                    ef:1b:b2:01:71:f1:fe:e4:64:76:ad:82:43:fd:81:
                    5d:61:e3:cb:e4:01:07:5e:6f:48:64:b1:f4:05:14:
                    86:a1:75:2f:01:10:ed:9a:d6:9c:0a:cd:5f:ea:d1:
                    d3:25:0e:20:97:01:af:eb:e5:49:1f:c2:e0:3c:e1:
                    7c:48:cb:72:6e:68:c3:12:2a:3d:b1:72:24:81:a6:
                    4a:1e:c8:6c:40:43:af:d4:09:04:ef:f6:73:ea:8b:
                    96:b1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                20:E8:25:22:E0:91:AD:40:E0:7E:23:78:D7:F6:47:55:2C:8F:05:4C
            X509v3 Authority Key Identifier:
                keyid:C6:BA:1E:48:92:8B:43:54:07:74:80:79:16:92:55:CA:EC:7D:D0:35

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
    Signature Algorithm: sha256WithRSAEncryption
        b7:0d:a3:d0:2a:3f:22:53:b3:42:e7:b6:fc:10:74:0a:c9:37:
        56:10:37:63:e2:33:8f:9d:57:49:17:68:82:33:01:34:35:5d:
        3c:c9:9e:3c:0b:3b:c9:91:b7:a4:a7:ce:a8:c1:45:66:d0:f1:
        8f:d0:02:86:c1:07:bf:38:d0:9d:5e:ea:47:8f:e4:96:e4:da:
        24:3d:c3:5e:49:ed:92:0e:c9:6f:1c:2f:ba:30:3c:a7:57:77:
        67:8c:7d:b2:99:c4:4d:c3:a1:e2:7e:31:5e:2e:b2:5e:26:d4:
        b3:9b:9c:40:bc:23:93:dd:1a:90:7a:19:a9:99:07:65:eb:24:
        c8:dc:42:1f:27:2a:45:75:5f:38:52:d9:ef:98:39:c3:80:4b:
        90:d3:d1:1c:65:f5:cc:f0:00:05:8f:4f:97:f0:19:f4:45:28:
        46:7e:e9:1d:cb:94:66:9b:da:da:af:99:8c:27:00:73:65:45:
        9d:67:c8:52:64:d9:a1:f0:e2:f1:4b:53:06:28:25:af:2a:d1:
        b8:c0:6e:71:33:42:a9:4a:f4:ac:25:3a:96:7e:83:1f:aa:7a:
        46:3d:fe:25:52:65:6a:47:49:a7:5b:5e:b0:c3:ec:b2:ad:8b:
        9f:23:42:f1:ec:93:88:4d:c1:35:3c:c1:18:33:ab:52:d2:aa:
        7b:8f:e1:fa
-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZaQ3J5
cHRvIFJvb3QgQXV0aG9yaXR5MB4XDTIwMDEwMTAwMDAwMFoXDTI2MTIzMTAwMDAw
MFowITEfMB0GA1UEAwwWWkNyeXB0byBSb290IEF1dGhvcml0eTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMxcjv3RCUTlpleWsccTNrhfx1yxKg+Pblr0
8zjZGFcIPV6H+roJTDYUQDJM/0bHF/bdPwKO2k9bPZYBZVgyxkyyvWXHkrIgKyMd
78UHdUz1Um1tXBoY54j453ZR5khhWtmUxWzAQSLypkeq6fy/pNMwJMmGw9UkPpw4
2xDle3HcFaGoSAVt/DIZD8wodXUfXSuY3rgMLrX0S79xE74+nDLSTxc97xuyAXHx
/uRkdq2CQ/2BXWHjy+QBB15vSGSx9AUUhqF1LwEQ7ZrWnArNX+rR0yUOIJcBr+vl
SR/C4DzhfEjLcm5owxIqPbFyJIGmSh7IbEBDr9QJBO/2c+qLlrECAwEAAaNjMGEw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIOglIuCRrUDgfiN41/ZHVSyPBUww
HwYDVR0jBBgwFoAUxroeSJKLQ1QHdIB5FpJVyux90DUwDgYDVR0PAQH/BAQDAgEG
MA0GCSqGSIb3DQEBCwUAA4IBAQC3DaPQKj8iU7NC57b8EHQKyTdWEDdj4jOPnVdJ
F2iCMwE0NV08yZ48CzvJkbekp86owUVm0PGP0AKGwQe/ONCdXupHj+SW5NokPcNe
Se2SDslvHC+6MDynV3dnjH2ymcRNw6HifjFeLrJeJtSzm5xAvCOT3RqQehmpmQdl
6yTI3EIfJypFdV84UtnvmDnDgEuQ09EcZfXM8AAFj0+X8Bn0RShGfukdy5Rmm9ra
r5mMJwBzZUWdZ8hSZNmh8OLxS1MGKCWvKtG4wG5xM0KpSvSsJTqWfoMfqnpGPf4l
UmVqR0mnW16ww+yyrYufI0Lx7JOITcE1PMEYM6tS0qp7j+H6
-----END CERTIFICATE-----
`
const zcryptoNeverValid = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 255 (0xff)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ZCrypto Root Authority
        Validity
            Not Before: Jan  1 01:00:00 2022 GMT
            Not After : Jan  1 01:00:00 2021 GMT
        Subject: CN=never-valid.example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d5:03:f6:b2:8b:f2:ee:f6:38:37:83:42:42:37:
                    11:3a:84:e5:43:49:92:ab:ed:0d:fb:1a:1f:31:e1:
                    d3:1d:0e:b8:6b:9a:9b:9c:f5:8e:2c:07:79:2d:a9:
                    7e:30:c6:c7:12:c6:78:43:17:f8:5f:8f:bb:d5:24:
                    15:9d:4e:6b:d7:fd:0d:34:0e:b7:73:7e:fa:54:b3:
                    d0:b2:2e:9b:97:80:85:8b:18:c8:ce:3d:e6:14:e8:
                    5f:9f:87:7c:04:78:76:c2:1d:f6:41:4c:4a:55:09:
                    cc:13:13:bd:88:8a:23:e6:e1:ee:c7:9e:de:0e:69:
                    87:96:cb:ee:a2:25:8f:67:ab:d3:be:64:c3:73:bb:
                    44:a3:a4:72:a0:c1:4d:07:e3:58:2f:f6:fb:05:1b:
                    bc:56:3c:61:e1:4c:ed:8e:a6:5d:05:83:ab:89:0d:
                    73:8a:27:db:89:56:c2:c5:79:4d:fc:92:06:8f:1b:
                    87:df:18:6c:32:66:5e:3a:6d:09:54:42:87:b7:90:
                    e6:c6:f9:9c:23:d5:85:ce:92:65:89:1a:71:98:e8:
                    9a:34:e8:d3:a4:b4:51:77:88:4a:86:98:2a:51:11:
                    08:1e:eb:91:c2:12:ae:44:60:3c:d8:38:7b:60:26:
                    43:2d:fd:c8:3e:d9:28:fb:f8:63:e7:b3:79:5a:bd:
                    40:83
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                20:B2:56:5B:CC:07:3D:03:5E:D4:9B:D8:09:75:CB:E0:5E:02:52:81
            X509v3 Authority Key Identifier:
                keyid:20:E8:25:22:E0:91:AD:40:E0:7E:23:78:D7:F6:47:55:2C:8F:05:4C

            X509v3 Key Usage:
                Digital Signature, Key Encipherment, Data Encipherment
    Signature Algorithm: sha256WithRSAEncryption
        51:e3:34:a3:df:5d:81:a8:57:af:2a:30:75:f6:f6:a7:83:a7:
        19:2a:a9:e9:e5:03:bc:7b:48:96:72:a4:05:ec:9e:99:d9:0f:
        93:b9:8a:42:80:a9:21:7d:1a:1d:d2:3b:68:58:8f:81:26:93:
        a1:91:a7:ab:aa:24:42:7e:5c:b0:50:ca:9e:cf:03:37:81:fe:
        ce:d1:a3:94:a9:5b:39:19:c1:5b:c6:18:18:71:8a:fa:08:c2:
        94:f5:92:d4:13:16:ad:05:72:fa:6d:f4:1e:fa:87:8f:0b:8c:
        cb:dd:2c:be:cb:f3:6f:55:f5:3c:c2:5b:e1:a5:14:28:21:f3:
        42:fb:76:07:f6:12:18:23:6e:39:2d:b5:fa:b6:78:35:c6:a1:
        e7:c5:ba:8e:76:dd:f1:e2:d9:2c:a4:bb:67:f8:68:4a:bf:f6:
        2f:dd:ac:a9:05:ba:4f:36:ab:0d:e9:da:6c:80:5a:7c:3a:bc:
        29:91:37:10:68:4f:27:43:af:68:88:17:8d:be:7f:7b:70:8b:
        99:38:f6:19:d8:f4:0c:72:8f:1f:d0:96:c0:65:39:1b:22:21:
        07:bc:10:39:f0:e7:b6:ea:a5:64:c8:da:e3:75:02:31:5f:a9:
        5c:2a:2b:b0:c5:e0:f8:bf:75:83:d8:da:73:c3:35:b2:0d:7f:
        2d:68:54:ce
-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgICAP8wDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWWkNy
eXB0byBSb290IEF1dGhvcml0eTAeFw0yMjAxMDEwMTAwMDBaFw0yMTAxMDEwMTAw
MDBaMCIxIDAeBgNVBAMMF25ldmVyLXZhbGlkLmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1QP2sovy7vY4N4NCQjcROoTlQ0mSq+0N
+xofMeHTHQ64a5qbnPWOLAd5Lal+MMbHEsZ4Qxf4X4+71SQVnU5r1/0NNA63c376
VLPQsi6bl4CFixjIzj3mFOhfn4d8BHh2wh32QUxKVQnMExO9iIoj5uHux57eDmmH
lsvuoiWPZ6vTvmTDc7tEo6RyoMFNB+NYL/b7BRu8Vjxh4UztjqZdBYOriQ1ziifb
iVbCxXlN/JIGjxuH3xhsMmZeOm0JVEKHt5DmxvmcI9WFzpJliRpxmOiaNOjTpLRR
d4hKhpgqUREIHuuRwhKuRGA82Dh7YCZDLf3IPtko+/hj57N5Wr1AgwIDAQABo10w
WzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQgslZbzAc9A17Um9gJdcvgXgJSgTAf
BgNVHSMEGDAWgBQg6CUi4JGtQOB+I3jX9kdVLI8FTDALBgNVHQ8EBAMCBLAwDQYJ
KoZIhvcNAQELBQADggEBAFHjNKPfXYGoV68qMHX29qeDpxkqqenlA7x7SJZypAXs
npnZD5O5ikKAqSF9Gh3SO2hYj4Emk6GRp6uqJEJ+XLBQyp7PAzeB/s7Ro5SpWzkZ
wVvGGBhxivoIwpT1ktQTFq0Fcvpt9B76h48LjMvdLL7L829V9TzCW+GlFCgh80L7
dgf2Ehgjbjkttfq2eDXGoefFuo523fHi2Syku2f4aEq/9i/drKkFuk82qw3p2myA
Wnw6vCmRNxBoTydDr2iIF42+f3twi5k49hnY9Axyjx/QlsBlORsiIQe8EDnw57bq
pWTI2uN1AjFfqVwqK7DF4Pi/dYPY2nPDNbINfy1oVM4=
-----END CERTIFICATE-----
`
const zcryptoValidBeforeIntermediate = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 256 (0x100)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ZCrypto Root Authority
        Validity
            Not Before: Jan  1 01:00:00 2018 GMT
            Not After : Jan  1 01:00:00 2019 GMT
        Subject: CN=never-valid.example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:c7:9d:77:33:b2:88:2a:62:49:7e:99:af:53:76:
                    64:eb:30:92:81:fc:f1:81:a5:38:58:19:3e:60:6d:
                    f4:47:8f:c3:76:37:72:a1:8e:29:e6:a8:f2:e1:a4:
                    89:71:b9:ec:c2:57:1d:62:bc:ae:2c:e4:1b:89:fd:
                    2c:75:17:11:95:d0:7f:7c:1b:ef:a6:9b:02:71:19:
                    3c:21:58:38:71:72:79:32:0d:3a:5e:15:67:01:e9:
                    f9:97:1e:fd:40:34:06:17:50:78:b2:e7:c5:48:6c:
                    d7:b2:02:e9:8d:2b:55:e9:a9:f9:37:71:3b:9c:99:
                    7e:31:6e:28:57:d6:68:00:50:c9:69:8d:e6:fd:0c:
                    7b:c4:46:6c:07:99:a2:24:1f:64:2e:0a:cb:c5:8f:
                    93:c9:00:4c:cc:23:e0:e6:d8:ed:10:0e:eb:e1:24:
                    3d:51:ba:55:8f:42:3b:0a:dc:a3:ec:fc:86:5d:93:
                    0c:1b:10:48:b4:80:30:74:3e:8b:4a:83:1e:79:ff:
                    d3:7c:30:27:68:97:14:54:fc:cd:0f:5f:c4:55:7b:
                    05:10:60:60:ea:32:e1:d9:b5:71:72:01:69:56:a5:
                    6e:90:fa:18:3a:34:9c:9a:af:b8:79:6a:52:9c:b9:
                    5b:92:9a:be:cf:40:1b:2d:c0:78:21:a4:a3:06:35:
                    4f:9b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                97:04:9A:93:E0:04:5A:73:DA:8B:AA:27:E1:E4:26:97:24:A1:C8:50
            X509v3 Authority Key Identifier:
                keyid:20:E8:25:22:E0:91:AD:40:E0:7E:23:78:D7:F6:47:55:2C:8F:05:4C

            X509v3 Key Usage:
                Digital Signature, Key Encipherment, Data Encipherment
    Signature Algorithm: sha256WithRSAEncryption
        5e:5b:93:3f:28:40:e3:7a:a2:38:6a:31:63:b1:ec:fb:c6:46:
        ae:8e:ad:c7:28:32:08:9d:14:a0:fa:81:64:de:b9:85:5d:54:
        8a:b1:14:22:a9:64:99:02:ca:8f:b4:ed:2d:6d:7a:fd:95:75:
        c7:5f:c5:42:30:f3:81:c4:6f:48:d4:86:ab:1c:16:1f:75:83:
        1f:58:9b:ac:91:a2:13:b2:79:4f:fd:06:ad:3f:b4:fa:99:23:
        9a:3d:74:de:b0:dc:a8:5d:ab:8c:d0:c5:05:d9:6f:3d:be:23:
        89:79:ac:d8:fb:16:b8:9d:8a:03:04:68:69:31:b0:cb:48:84:
        09:22:57:7c:4f:5c:bc:6b:84:93:42:46:82:f4:bb:30:70:5a:
        12:6f:26:5b:04:f3:06:4b:cb:8b:3e:0d:18:65:47:62:67:04:
        a9:cd:cf:7e:d5:cb:c8:1e:94:18:52:8b:f8:41:f1:e6:e6:61:
        df:67:2e:c0:75:17:29:3c:c4:e3:c6:4c:fa:54:6d:14:5f:9f:
        9b:ad:89:db:b7:92:ba:e7:88:46:88:04:b1:1c:83:8d:f1:2f:
        4a:30:e2:63:e8:53:7d:05:68:65:b6:f7:3b:a8:3e:d9:dc:47:
        fa:55:66:ef:8f:dd:ec:1f:a8:98:1e:55:c0:dd:21:41:e1:83:
        f5:f3:26:ff
-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgICAQAwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWWkNy
eXB0byBSb290IEF1dGhvcml0eTAeFw0xODAxMDEwMTAwMDBaFw0xOTAxMDEwMTAw
MDBaMCIxIDAeBgNVBAMMF25ldmVyLXZhbGlkLmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx513M7KIKmJJfpmvU3Zk6zCSgfzxgaU4
WBk+YG30R4/DdjdyoY4p5qjy4aSJcbnswlcdYryuLOQbif0sdRcRldB/fBvvppsC
cRk8IVg4cXJ5Mg06XhVnAen5lx79QDQGF1B4sufFSGzXsgLpjStV6an5N3E7nJl+
MW4oV9ZoAFDJaY3m/Qx7xEZsB5miJB9kLgrLxY+TyQBMzCPg5tjtEA7r4SQ9UbpV
j0I7Ctyj7PyGXZMMGxBItIAwdD6LSoMeef/TfDAnaJcUVPzND1/EVXsFEGBg6jLh
2bVxcgFpVqVukPoYOjScmq+4eWpSnLlbkpq+z0AbLcB4IaSjBjVPmwIDAQABo10w
WzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSXBJqT4ARac9qLqifh5CaXJKHIUDAf
BgNVHSMEGDAWgBQg6CUi4JGtQOB+I3jX9kdVLI8FTDALBgNVHQ8EBAMCBLAwDQYJ
KoZIhvcNAQELBQADggEBAF5bkz8oQON6ojhqMWOx7PvGRq6OrccoMgidFKD6gWTe
uYVdVIqxFCKpZJkCyo+07S1tev2VdcdfxUIw84HEb0jUhqscFh91gx9Ym6yRohOy
eU/9Bq0/tPqZI5o9dN6w3Khdq4zQxQXZbz2+I4l5rNj7FridigMEaGkxsMtIhAki
V3xPXLxrhJNCRoL0uzBwWhJvJlsE8wZLy4s+DRhlR2JnBKnNz37Vy8gelBhSi/hB
8ebmYd9nLsB1Fyk8xOPGTPpUbRRfn5utidu3krrniEaIBLEcg43xL0ow4mPoU30F
aGW29zuoPtncR/pVZu+P3ewfqJgeVcDdIUHhg/XzJv8=
-----END CERTIFICATE-----
`
