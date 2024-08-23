// ZCrypto Copyright 2019 Regents of the University of Michigan
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy
// of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package x509 implements a lenient X509 parser
package x509

import (
	"errors"

	"github.com/zmap/zcrypto/v2/zcryptobyte"
	"github.com/zmap/zcrypto/v2/zcryptobyte/asn1"
)

// Certificate  ::=  SEQUENCE  {
//     tbsCertificate       TBSCertificate,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signature            BIT STRING  }
//
// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }
//                                 -- contains a value of the type
//                                 -- registered for use with the
//                                 -- algorithm object identifier value

// Certificate matches the core `Certificate` SEQUENCE from RFC 5280.
type Certificate struct {
	RawTBSCertificate []byte
	TBSCertificate    TBSCertificate

	RawSignatureAlgorithm []byte
	SignatureAlgorithm    AlgorithmIdentifier

	RawSignature []byte
	Signature    BitString
}

func ParseCertificate(b []byte) (*Certificate, error) {
	var c Certificate
	s := zcryptobyte.String(b)

	// A CERTFIICATE is a SEQUENCE, so pull off the header and get a pointer to
	// the start of the contents of the sequence.
	var contents zcryptobyte.String
	var tag asn1.Tag
	var n uint32
	var err error

	var certificate zcryptobyte.String
	var totalLen uint32
	n, err = s.ReadAnyASN1(&certificate, nil, &contents, &tag)
	totalLen += n
	if err != nil {
		return &c, err
	}

	var tbsCertificate, algorithmIdentifier, signature zcryptobyte.String
	n, err = contents.ReadAnyASN1(&tbsCertificate, nil, nil, &tag)
	totalLen += n
	if err != nil {
		return &c, InvalidASN1("tbsCertificate", err)
	}
	n, err = contents.ReadAnyASN1(&algorithmIdentifier, nil, nil, &tag)
	totalLen += n
	if err != nil {
		return &c, InvalidASN1("algorithmIdentifier", err)
	}
	n, err = contents.ReadAnyASN1(&signature, nil, nil, &tag)
	totalLen += n
	if err != nil {
		return &c, InvalidASN1("signature", err)
	}

	c.RawTBSCertificate = tbsCertificate
	c.RawSignatureAlgorithm = algorithmIdentifier
	c.RawSignature = signature

	return &c, nil
}

// TBSCertificate  ::=  SEQUENCE  {
//   version         [0]  Version DEFAULT v1,
//   serialNumber         CertificateSerialNumber,
//   signature            AlgorithmIdentifier,
//   issuer               Name,
//   validity             Validity,
//   subject              Name,
//   subjectPublicKeyInfo SubjectPublicKeyInfo,
//   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                       -- If present, version MUST be v2 or v3
//   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                       -- If present, version MUST be v2 or v3
//   extensions      [3]  Extensions OPTIONAL
//                       -- If present, version MUST be v3 --  }

type TBSCertificate struct {
	Version              int64
	SerialNumber         CertificateSerialNumber
	Signature            AlgorithmIdentifier
	Issuer               Name
	Validity             Validity
	Subject              Name
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	IssuerUniqueID       UniqueIdentifier
	SubjectUniqueID      UniqueIdentifier
	Extensions           Extensions

	RawVersion              []byte
	RawSerialNumber         []byte
	RawSignature            []byte
	RawIssuer               []byte
	RawValidity             []byte
	RawSubject              []byte
	RawSubjectPublicKeyInfo []byte
	RawIssuerUniqueID       []byte
	RawSubjectUniqueID      []byte
	RawExtensions           []byte
}

func ParseTBSCertificate(b []byte) (*TBSCertificate, error) {
	var tbs TBSCertificate
	var err error

	it := b

	tbs.Version, tbs.RawVersion, err = ParseVersion(it)
	if err != nil {
		return nil, err
	}
	it = it[len(tbs.RawVersion):]

	tbs.SerialNumber, tbs.RawSerialNumber, err = ParseSerialNumber(it)
	if err != nil {
		return nil, err
	}

	return &tbs, nil
}

func checkASN1Integer(b []byte) bool {
	// An ASN.1 INTEGER should never be empty. It should also be "minimally
	// encoded", however we're not going to enforce that here.
	return len(b) > 0
}

func asn1Signed(out *int64, n []byte) bool {
	length := len(n)
	if length > 8 {
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= int64(n[i])
	}
	// Shift up and down in order to sign extend the result.
	*out <<= 64 - uint8(length)*8
	*out >>= 64 - uint8(length)*8
	return true
}

func readASN1IntegerWithTag(out *zcryptobyte.String, in zcryptobyte.String, tag asn1.Tag) (v int64, err error) {
	// TODO(dadrian)[2024-08-04]: The validation methods should propagate the
	// real ASN.1 error up, instead of inferring it on the next line.
	_, err = in.ReadTaggedASN1(nil, out, tag)
	if err != nil {
		return 0, err
	}
	ok := checkASN1Integer(*out) && asn1Signed(&v, *out)
	if !ok {
		return 0, asn1.ErrInvalidInteger
	}
	return
}

func readASN1BigIntegerAsBytes(out *zcryptobyte.String, in zcryptobyte.String) error {
	return errors.New("unimplemented")
}

// ParseVersion returns an int64 representing the Version field in the
// tbsCertificate sequence.
func ParseVersion(b []byte) (v int64, raw []byte, err error) {
	s := zcryptobyte.String(b)
	var rawVersion zcryptobyte.String
	v, err = readASN1IntegerWithTag(&rawVersion, s, asn1.Tag(0))
	return v, rawVersion, err
}

func ParseSerialNumber(b []byte) (serial []byte, raw []byte, err error) {
	var out zcryptobyte.String
	err = readASN1BigIntegerAsBytes(&out, b)
	if err != nil {
		return nil, out, err
	}
	serial = out[1:]
	return serial, out, err
}

type AlgorithmIdentifier struct {
	AlgorithmIdentifier ObjectIdentifier
	Parameters          Parameters
}

type BitString []byte
type CertificateSerialNumber []byte
type Name []byte
type Validity []byte
type SubjectPublicKeyInfo []byte
type UniqueIdentifier []byte
type Extensions []byte
type ObjectIdentifier []byte
type Parameters []byte
