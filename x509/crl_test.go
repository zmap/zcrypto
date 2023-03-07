// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

const (
	// STARTBLOCK: This constant does not exist in upstream.
	derGenTimeZ0000Base64 = "MIIBSzCB0wIBATAKBggqhkjOPQQDAzBJMQswCQYDVQQGEwJYWDEVMBMGA1UEChMMQm91bGRlciBUZXN0MSMwIQYDVQQDExooVEVTVCkgRWxlZ2FudCBFbGVwaGFudCBFMRgTMjA1MDA3MDYxNjQzMzhaMDAwMBcNMjIwNzE1MTY0MzM4WjAbMBkCCAOuUdtRFVo8Fw0yMjA3MDYxNTQzMzhaoDYwNDAfBgNVHSMEGDAWgBQB2rt6yyUgjl551vmWQi8CQSkHvjARBgNVHRQECgIIFv9LJt+yGA8wCgYIKoZIzj0EAwMDZwAwZAIwVrITRYutGjFpfNht08CLsAQSvnc4i6UM0Pi8+U3T8DRHImIiuB9cQ+qxULB6pKhBAjBbuGCwTop7vCfGO7Fz6N0ruITInFtt6BDR5izWUMfXXa7mXhSQ6ig9hOHOWRxR00I="
	//This constant does not exist in upstream.
	derUTCTimeYYMMDDHHMMZTTBase64 = "MIIBRTCBzQIBATAKBggqhkjOPQQDAzBJMQswCQYDVQQGEwJYWDEVMBMGA1UEChMMQm91bGRlciBUZXN0MSMwIQYDVQQDExooVEVTVCkgRWxlZ2FudCBFbGVwaGFudCBFMRcNMjIwNzA2MTY0M1owOBcNMjIwNzE1MTY0MzM4WjAbMBkCCAOuUdtRFVo8Fw0yMjA3MDYxNTQzMzhaoDYwNDAfBgNVHSMEGDAWgBQB2rt6yyUgjl551vmWQi8CQSkHvjARBgNVHRQECgIIFv9LJt+yGA8wCgYIKoZIzj0EAwMDZwAwZAIwVrITRYutGjFpfNht08CLsAQSvnc4i6UM0Pi8+U3T8DRHImIiuB9cQ+qxULB6pKhBAjBbuGCwTop7vCfGO7Fz6N0ruITInFtt6BDR5izWUMfXXa7mXhSQ6ig9hOHOWRxR00I="
	// ENDBLOCK
)

func TestCreateRevocationList(t *testing.T) {
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P256 key: %s", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}
	reasonKeyCompromise := 1
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           ec256Priv,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           ec256Priv,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "long Number",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{1}, make([]byte, 20)...)),
			},
			expectedError: "x509: CRL number exceeds 20 octets",
		},
		{
			name: "long Number (20 bytes, MSB set)",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{255}, make([]byte, 19)...)),
			},
			expectedError: "x509: CRL number exceeds 20 octets",
		},
		{
			name: "valid",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, reason code",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ReasonCode:     &reasonKeyCompromise,
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra entry extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ReasonCode:     &reasonKeyCompromise,
						ExtraExtensions: []pkix.Extension{
							{
								Id:    []int{1, 1},
								Value: []byte{5, 0},
							},
						},
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, Ed25519 key",
			key:  ed25519Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: ECDSAWithSHA512,
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseRevocationList(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				parsedCRL.SignatureAlgorithm != tc.template.SignatureAlgorithm {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if len(parsedCRL.RevokedCertificates) != len(tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates length mismatch: got %d; want %d.",
					len(parsedCRL.RevokedCertificates), len(tc.template.RevokedCertificates))
			}
			for i, rc := range parsedCRL.RevokedCertificates {
				erc := tc.template.RevokedCertificates[i]
				if rc.SerialNumber.Cmp(erc.SerialNumber) != 0 {
					t.Errorf("RevokedCertificates entry %d serial mismatch: got %s; want %s.",
						i, rc.SerialNumber.String(), erc.SerialNumber.String())
				}
				if rc.RevocationTime != erc.RevocationTime {
					t.Errorf("RevokedCertificates entry %d date mismatch: got %v; want %v.",
						i, rc.RevocationTime, erc.RevocationTime)
				}
				numExtra := 0
				if erc.ReasonCode != nil {
					if rc.ReasonCode == nil {
						t.Errorf("RevokedCertificates entry %d reason mismatch: got nil; want %v.",
							i, *erc.ReasonCode)
					}
					if *rc.ReasonCode != *erc.ReasonCode {
						t.Errorf("RevokedCertificates entry %d reason mismatch: got %v; want %v.",
							i, *rc.ReasonCode, *erc.ReasonCode)
					}
					numExtra = 1
				} else {
					if rc.ReasonCode != nil {
						t.Errorf("RevokedCertificates entry %d reason mismatch: got %v; want nil.",
							i, *rc.ReasonCode)
					}
				}
				if len(rc.Extensions) != numExtra+len(erc.ExtraExtensions) {
					t.Errorf("RevokedCertificates entry %d has wrong number of extensions: got %d; want %d",
						i, len(rc.Extensions), numExtra+len(erc.ExtraExtensions))
				}
			}

			if len(parsedCRL.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.Extensions[1], crlExt)
			}
			if len(parsedCRL.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}

func TestParseRevocationList(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseRevocationList(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.RevokedCertificates)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	// STARTBLOCK: This block does not exist in upstream.
	// Check that 'thisUpdate' of 'GENERALIZEDTIME 20500706164338Z0000' (time
	// zone is UTC but also explicitly specified) is considered invalid.
	derBytes = fromBase64(derGenTimeZ0000Base64)
	_, err = ParseRevocationList(derBytes)
	assertError(t, err, "expected error parsing CRL")
	assertContains(t, err.Error(), "x509: malformed GeneralizedTime")

	// Check that 'thisUpdate' of 'UTCTIME 2207061643Z08' (YYMMDDHHMMZTT) is
	// considered invalid.
	derBytes = fromBase64(derUTCTimeYYMMDDHHMMZTTBase64)
	_, err = ParseRevocationList(derBytes)
	assertContains(t, err.Error(), "x509: malformed UTCTime")
	// ENDBLOCK
}

func TestRevocationListCheckSignatureFrom(t *testing.T) {
	goodKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	badKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	tests := []struct {
		name   string
		issuer *Certificate
		err    string
	}{
		{
			name: "valid",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
			},
		},
		{
			name: "valid, key usage set",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              KeyUsageCRLSign,
			},
		},
		{
			name: "invalid issuer, wrong key usage",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              KeyUsageCertSign,
			},
			err: "x509: invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, no basic constraints/ca",
			issuer: &Certificate{
				Version:            3,
				PublicKeyAlgorithm: ECDSA,
				PublicKey:          goodKey.Public(),
			},
			err: "x509: invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, unsupported public key type",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    UnknownPublicKeyAlgorithm,
				PublicKey:             goodKey.Public(),
			},
			err: "x509: cannot verify signature: algorithm unimplemented",
		},
		{
			name: "wrong key",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             badKey.Public(),
			},
			err: "x509: ECDSA verification failure",
		},
	}

	crlIssuer := &Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKeyAlgorithm:    ECDSA,
		PublicKey:             goodKey.Public(),
		KeyUsage:              KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crlDER, err := CreateRevocationList(rand.Reader, &RevocationList{Number: big.NewInt(1)}, crlIssuer, goodKey)
			if err != nil {
				t.Fatalf("failed to generate CRL: %s", err)
			}
			crl, err := ParseRevocationList(crlDER)
			if err != nil {
				t.Fatalf("failed to parse test CRL: %s", err)
			}
			err = crl.CheckSignatureFrom(tc.issuer)
			if err != nil && err.Error() != tc.err {
				t.Errorf("unexpected error: got %s, want %s", err, tc.err)
			} else if err == nil && tc.err != "" {
				t.Errorf("CheckSignatureFrom did not fail: want %s", tc.err)
			}
		})
	}
}

func assertError(t testing.TB, err error, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error but received none", message)
	}
}

// AssertContains determines whether needle can be found in haystack
func assertContains(t testing.TB, haystack string, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("String [%s] does not contain [%s]", haystack, needle)
	}
}
