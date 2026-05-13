// Copyright 2024 The zcrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

// Tests for RSA certificates whose public exponent E is too large to fit in a
// Go int.  Such certificates exist in the wild and were previously causing
// ParseCertificate to return an "integer too large" error, discarding the
// entire certificate rather than preserving the raw bytes.
//
// See: https://github.com/runZeroInc/sshamble/issues/43

import (
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509/pkix"
)

var (
	oidRSAEncryption        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSAEncrypt = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// buildLargeERSACertDER returns a minimal DER-encoded self-signed X.509
// certificate whose RSA public exponent equals e.  The signature is dummy
// bytes; this cert is only meant to exercise the parser.
func buildLargeERSACertDER(t *testing.T, e *big.Int) []byte {
	t.Helper()

	// 2048-bit RSA modulus (arbitrary, not a real key).
	nHex := "00d73978d2935e3fc2cf4a5d8c2174d8ae9c7e6f" +
		"2f1f5e29be2b1d52f3fdcb3fad5" +
		"5e4c9b5e7a7e36c1e4c0578e4cd0" +
		"8f1b8ee3e428a9abcdef01234567" +
		"89abcdef01234567890123456789" +
		"abcdef0123456789012345678901" +
		"23456789abcdef0123456789abcd" +
		"ef0123456789abcdef01234567"
	n := new(big.Int)
	n.SetBytes(func() []byte {
		// 256 bytes (2048-bit) of deterministic non-zero modulus material.
		b := make([]byte, 256)
		for i := range b {
			b[i] = byte(0xa5 + i)
		}
		b[0] |= 0x80 // ensure high bit set so it's genuinely 2048-bit
		return b
	}())
	_ = nHex // avoid unused-variable error on the const above

	// Marshal the RSA public key with the (potentially large) exponent.
	pubKeyDER, err := asn1.Marshal(pkcs1PublicKey{N: n, E: e})
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}

	spki := publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.RawValue{Tag: 5}, // NULL
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyDER,
			BitLength: len(pubKeyDER) * 8,
		},
	}

	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	issuerRDN, err := asn1.Marshal(pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			{Type: []int{2, 5, 4, 3}, Value: "Large-E Test"},
		},
	})
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}

	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256WithRSAEncrypt,
		},
		Issuer:    asn1.RawValue{FullBytes: issuerRDN},
		Validity:  validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:   asn1.RawValue{FullBytes: issuerRDN},
		PublicKey: spki,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal TBS certificate: %v", err)
	}

	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256WithRSAEncrypt,
		},
		// Dummy signature — we only test parsing, not verification.
		SignatureValue: asn1.BitString{
			Bytes:     make([]byte, 256),
			BitLength: 256 * 8,
		},
	}
	_ = tbsDER

	certDER, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	return certDER
}

// TestParseLargeRSAExponent verifies that ParseCertificate succeeds for
// certificates with RSA public exponents that do not fit in a Go int.
func TestParseLargeRSAExponent(t *testing.T) {
	tests := []struct {
		name string
		e    *big.Int
	}{
		{name: "standard e=65537", e: big.NewInt(65537)},
		{name: "e just above int32 max (2^31)", e: new(big.Int).Add(big.NewInt(1<<31), big.NewInt(1))},
		{name: "e above 2^33", e: new(big.Int).Lsh(big.NewInt(1), 33)},
		{name: "e above 2^62", e: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 63), big.NewInt(1))},
		{name: "e larger than int64 (2^64)", e: new(big.Int).Lsh(big.NewInt(1), 64)},
		{name: "e very large (2^128)", e: new(big.Int).Lsh(big.NewInt(1), 128)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der := buildLargeERSACertDER(t, tc.e)

			c, err := ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate failed: %v", err)
			}

			// Raw SPKI bytes must always be present regardless of exponent size.
			if len(c.RawSubjectPublicKeyInfo) == 0 {
				t.Error("RawSubjectPublicKeyInfo is empty")
			}

			// The public key struct itself must be present.
			if c.PublicKey == nil {
				t.Fatal("PublicKey is nil")
			}

			// ZCrypto - parsePublicKey now returns *zrsa.PublicKey so E *big.Int is preserved.
			rsaPub, ok := c.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("PublicKey is %T, want *zrsa.PublicKey", c.PublicKey)
			}

			if rsaPub.N == nil || rsaPub.N.Sign() <= 0 {
				t.Error("RSA modulus N is nil or non-positive")
			}

			if rsaPub.E == nil {
				t.Fatal("E is nil")
			}
			if rsaPub.E.Cmp(tc.e) != 0 {
				t.Errorf("E = %s, want %s", rsaPub.E, tc.e)
			}
		})
	}
}
