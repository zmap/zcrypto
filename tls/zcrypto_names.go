// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"strconv"
	"strings"
)

//go:generate ./tls_cipher_suites.py tls_cipher_suites.go

var signatureNames map[uint8]string
var hashNames map[uint8]string
var compressionNames map[uint8]string
var curveNames map[uint16]string
var pointFormatNames map[uint8]string
var clientAuthTypeNames map[int]string
var signatureSchemeNames map[uint16]string

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureAnonymous uint8 = 0
	signatureRSA       uint8 = 1
	signatureDSA       uint8 = 2
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashMD5    uint8 = 1
	hashSHA1   uint8 = 2
	hashSHA224 uint8 = 3
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
	hashSHA512 uint8 = 6
)

func init() {
	// RFC 5246 7.4.1.4.1
	signatureNames = make(map[uint8]string, 8)
	// TODO FIXME: the RFC also defines anonymous(0) and (255).
	signatureNames[signatureRSA] = "rsa"
	signatureNames[signatureDSA] = "dsa"
	signatureNames[signatureECDSA] = "ecdsa"

	// RFC 5246 7.4.1.4.1
	hashNames = make(map[uint8]string, 16)
	// TODO FIXME: the RFC also defines none(0) and (255).
	hashNames[hashMD5] = "md5"
	hashNames[hashSHA1] = "sha1"
	hashNames[hashSHA224] = "sha224"
	hashNames[hashSHA256] = "sha256"
	hashNames[hashSHA384] = "sha384"
	hashNames[hashSHA512] = "sha512"

	// https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml#comp-meth-ids-2
	compressionNames = make(map[uint8]string)
	compressionNames[0] = "NULL"
	compressionNames[1] = "DEFLATE"
	compressionNames[64] = "LZS"

	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
	curveNames = make(map[uint16]string)
	curveNames[1] = "sect163k1"
	curveNames[2] = "sect163r1"
	curveNames[3] = "sect163r2"
	curveNames[4] = "sect193r1"
	curveNames[5] = "sect193r2"
	curveNames[6] = "sect233k1"
	curveNames[7] = "sect233r1"
	curveNames[8] = "sect239k1"
	curveNames[9] = "sect283k1"
	curveNames[10] = "sect283r1"
	curveNames[11] = "sect409k1"
	curveNames[12] = "sect409r1"
	curveNames[13] = "sect571k1"
	curveNames[14] = "sect571r1"
	curveNames[15] = "secp160k1"
	curveNames[16] = "secp160r1"
	curveNames[17] = "secp160r2"
	curveNames[18] = "secp192k1"
	curveNames[19] = "secp192r1"
	curveNames[20] = "secp224k1"
	curveNames[21] = "secp224r1"
	curveNames[22] = "secp256k1"
	curveNames[23] = "secp256r1"
	curveNames[24] = "secp384r1"
	curveNames[25] = "secp521r1"
	curveNames[26] = "brainpoolP256r1"
	curveNames[27] = "brainpoolP384r1"
	curveNames[28] = "brainpoolP512r1"
	curveNames[29] = "ecdh_x25519" // TEMPORARY -- expires 1Mar2018
	curveNames[30] = "ecdh_x448"   // TEMPORARY -- expires 1Mar2018
	curveNames[256] = "ffdhe2048"
	curveNames[257] = "ffdhe3072"
	curveNames[258] = "ffdhe4096"
	curveNames[259] = "ffdhe6144"
	curveNames[260] = "ffdhe8192"
	curveNames[65281] = "arbitrary_explicit_prime_curves"
	curveNames[65282] = "arbitrary_explicit_char2_curves"

	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
	pointFormatNames = make(map[uint8]string)
	pointFormatNames[0] = "uncompressed"
	pointFormatNames[1] = "ansiX962_compressed_prime"
	pointFormatNames[2] = "ansiX962_compressed_char2"

	// Name-value paires *are* not standardized, only dereferenced for JSON output
	clientAuthTypeNames = make(map[int]string)
	clientAuthTypeNames[0] = "NoClientCert"
	clientAuthTypeNames[1] = "RequestClientCert"
	clientAuthTypeNames[2] = "RequireAnyClientCert"
	clientAuthTypeNames[3] = "VerifyClientCertIfGiven"
	clientAuthTypeNames[4] = "RequireAndVerifyClientCert"

	// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3
	signatureSchemeNames = make(map[uint16]string)
	signatureSchemeNames[uint16(PKCS1WithSHA1)] = "rsa_pkcs1_sha1"
	signatureSchemeNames[uint16(PKCS1WithSHA256)] = "rsa_pkcs1_sha256"
	signatureSchemeNames[uint16(PKCS1WithSHA384)] = "rsa_pkcs1_sha384"
	signatureSchemeNames[uint16(PKCS1WithSHA512)] = "rsa_pkcs1_sha512"
	signatureSchemeNames[uint16(PSSWithSHA256)] = "rsa_pss_sha256"
	signatureSchemeNames[uint16(PSSWithSHA384)] = "rsa_pss_sha384"
	signatureSchemeNames[uint16(PSSWithSHA512)] = "rsa_pss_sha512"
	signatureSchemeNames[uint16(ECDSAWithP256AndSHA256)] = "ecdsa_secp256r1_sha256"
	signatureSchemeNames[uint16(ECDSAWithP384AndSHA384)] = "ecdsa_secp384r1_sha384"
	signatureSchemeNames[uint16(ECDSAWithP521AndSHA512)] = "ecdsa_secp521r1_sha512"
}

func nameForSignature(s uint8) string {
	if name, ok := signatureNames[s]; ok {
		return name
	}
	return "unknown." + strconv.Itoa(int(s))
}

func nameForHash(h uint8) string {
	if name, ok := hashNames[h]; ok {
		return name
	}
	num := strconv.Itoa(int(h))
	return "unknown." + num
}

func signatureFromName(n string) uint8 {
	for k, v := range signatureNames {
		if v == n {
			return k
		}
	}
	s, _ := strconv.ParseInt(strings.TrimPrefix(n, "unknown."), 10, 32)
	return uint8(s)
}

func hashFromName(n string) crypto.Hash {
	for k, v := range hashNames {
		if v == n {
			return crypto.Hash(k)
		}
	}
	h, _ := strconv.ParseInt(strings.TrimPrefix(n, "unknown."), 10, 32)
	return crypto.Hash(h)
}

func nameForSuite(cs uint16) string {
	cipher := CipherSuite(cs)
	return cipher.String()
}

func (cs CipherSuite) Bytes() []byte {
	return []byte{uint8(cs >> 8), uint8(cs)}
}

func (cs CipherSuite) String() string {
	if name, ok := cipherSuiteNames[int(cs)]; ok {
		return name
	}
	return "unknown"
}

func (cm CompressionMethod) String() string {
	if name, ok := compressionNames[uint8(cm)]; ok {
		return name
	}
	return "unknown"
}

func (curveID CurveID) String() string {
	if name, ok := curveNames[uint16(curveID)]; ok {
		return name
	}
	return "unknown"
}

func (pFormat PointFormat) String() string {
	if name, ok := pointFormatNames[uint8(pFormat)]; ok {
		return name
	}
	return "unknown"
}

func nameForCompressionMethod(cm uint8) string {
	compressionMethod := CompressionMethod(cm)
	return compressionMethod.String()
}

func nameForCurve(curveID uint16) string {
	curve := CurveID(curveID)
	return curve.String()
}

func nameForPointFormat(pFormat uint8) string {
	format := PointFormat(pFormat)
	return format.String()
}

func (v TLSVersion) Bytes() []byte {
	return []byte{uint8(v >> 8), uint8(v)}
}

func (v TLSVersion) String() string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLSv1.0"
	case VersionTLS11:
		return "TLSv1.1"
	case VersionTLS12:
		return "TLSv1.2"
	case VersionTLS13:
		return "TLSv1.3"
	default:
		return "unknown"
	}
}

func nameForSignatureScheme(scheme uint16) string {
	sigScheme := SignatureScheme(scheme)
	return sigScheme.String()
}

func (sigScheme *SignatureScheme) String() string {
	if name, ok := signatureSchemeNames[uint16(*sigScheme)]; ok {
		return name
	}
	return "unknown"
}

func (sigScheme *SignatureScheme) Bytes() []byte {
	return []byte{byte(*sigScheme >> 8), byte(*sigScheme)}
}
