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
	"math/big"

	encoding_asn1 "encoding/asn1"

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

func ParseCertificate(b []byte) (n uint32, c *Certificate, err error) {
	c = &Certificate{}
	s := zcryptobyte.String(b)

	// A CERTFIICATE is a SEQUENCE, so pull off the header and get a pointer to
	// the start of the contents of the sequence.
	var contents zcryptobyte.String
	var tag asn1.Tag

	var certificate zcryptobyte.String
	n, err = s.ReadAnyASN1(&certificate, nil, &contents, &tag)
	if err != nil {
		return
	}

	var tbsCertificate, algorithmIdentifier, signature zcryptobyte.String
	_, err = contents.ReadAnyASN1(&tbsCertificate, nil, nil, &tag)
	if err != nil {
		err = InvalidASN1("tbsCertificate", err)
		return
	}
	_, err = contents.ReadAnyASN1(&algorithmIdentifier, nil, nil, &tag)
	if err != nil {
		err = InvalidASN1("algorithmIdentifier", err)
		return
	}
	_, err = contents.ReadAnyASN1(&signature, nil, nil, &tag)
	if err != nil {
		err = InvalidASN1("signature", err)
		return
	}

	c.RawTBSCertificate = tbsCertificate
	c.RawSignatureAlgorithm = algorithmIdentifier
	c.RawSignature = signature

	err = parseTBSCertificate(tbsCertificate, nil, &c.TBSCertificate)
	return
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
	SignatureAlgorithm   AlgorithmIdentifier
	Issuer               Name
	Validity             Validity
	Subject              Name
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	IssuerUniqueID       UniqueIdentifier
	SubjectUniqueID      UniqueIdentifier
	Extensions           Extensions

	RawVersion              zcryptobyte.String
	RawSerialNumber         zcryptobyte.String
	RawSignature            zcryptobyte.String
	RawIssuer               zcryptobyte.String
	RawValidity             zcryptobyte.String
	RawSubject              zcryptobyte.String
	RawSubjectPublicKeyInfo zcryptobyte.String
	RawIssuerUniqueID       zcryptobyte.String
	RawSubjectUniqueID      zcryptobyte.String
	RawExtensions           zcryptobyte.String
}

func parseTBSCertificate(in zcryptobyte.String, out *zcryptobyte.String, parsed *TBSCertificate) (err error) {
	var it zcryptobyte.String
	var tbsHeader zcryptobyte.String
	var tbsTag asn1.Tag
	_, err = in.ReadAnyASN1(out, &tbsHeader, &it, &tbsTag)
	if err != nil {
		err = InvalidASN1("tbsCertificate:SEQUENCE", err)
		return
	}

	err = parseVersion(&it, &parsed.RawVersion, &parsed.Version)
	if err != nil {
		err = InvalidASN1("version", err)
		return
	}

	err = parseSerialNumber(&it, &parsed.RawSerialNumber, &parsed.SerialNumber)
	if err != nil {
		err = InvalidASN1("serialNumber", err)
		return
	}

	err = parseAlgorithmIdentifier(&it, &parsed.RawSignature, &parsed.SignatureAlgorithm)
	if err != nil {
		err = InvalidASN1("algorithmIdentifier", err)
		return
	}

	err = parseName(&it, &parsed.RawIssuer, &parsed.Issuer)
	if err != nil {
		err = InvalidASN1("issuer", err)
		return
	}

	err = parseValidity(&it, &parsed.RawValidity, &parsed.Validity)
	if err != nil {
		err = InvalidASN1("validity", err)
	}

	err = parseName(&it, &parsed.RawSubject, &parsed.Subject)
	if err != nil {
		err = InvalidASN1("subject", err)
		return
	}

	err = parseSubjectPublicKeyInfo(&it, &parsed.RawSubjectPublicKeyInfo, &parsed.SubjectPublicKeyInfo)
	if err != nil {
		err = InvalidASN1("subjectPublicKeyInfo", err)
		return
	}

	err = parseUniqueID(&it, &parsed.RawIssuerUniqueID, &parsed.IssuerUniqueID)
	if err != nil {
		err = InvalidASN1("issuerUniqueID", err)
		return
	}

	err = parseUniqueID(&it, &parsed.RawSubjectUniqueID, &parsed.SubjectUniqueID)
	if err != nil {
		err = InvalidASN1("subjectUniqueID", err)
		return
	}

	err = parseExtensions(&it, &parsed.RawExtensions, &parsed.Extensions)
	if err != nil {
		err = InvalidASN1("extensions", err)
		return
	}

	return
}

func ParseTBSCertificate(b []byte) (*TBSCertificate, error) {
	panic("unimplemented")
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

var bigOne = big.NewInt(1)

func readASN1BigIntegerAsBytes(in zcryptobyte.String, out *big.Int) (err error) {
	if len(in) < 1 {
		return asn1.ErrInvalidInteger
	}
	if in[0]&0x80 == 0x80 {
		// Negative number.
		neg := make([]byte, len(in))
		for i, b := range in {
			neg[i] = ^b
		}
		out.SetBytes(neg)
		out.Add(out, bigOne)
		out.Neg(out)
	} else {
		out.SetBytes(in)
	}
	return nil
}

func parseVersion(in *zcryptobyte.String, out *zcryptobyte.String, parsed *int64) (err error) {
	var data zcryptobyte.String
	var tag asn1.Tag
	// TODO(dadrian)[2024-10-21]: Move integer parsing to ZCryptobyte?
	_, err = in.ReadAnyASN1(out, nil, &data, &tag)
	if err != nil {
		return err
	}
	if !checkASN1Integer(data) || !asn1Signed(parsed, (data)) {
		return asn1.ErrInvalidInteger
	}
	// Turn `out` into an INTEGER
	return nil
}

func ParseVersion(in zcryptobyte.String) (parsed *int64, raw zcryptobyte.String, err error) {
	var v int64
	err = parseVersion(&in, &raw, &v)
	return &v, raw, err
}

func parseSerialNumber(in *zcryptobyte.String, out *zcryptobyte.String, parsed *CertificateSerialNumber) (err error) {
	var data zcryptobyte.String
	var tag asn1.Tag
	_, err = in.ReadAnyASN1(out, nil, &data, &tag)
	if err != nil {
		return err
	}
	// TODO(dadrian)[2024-10-22]: Move big integer parsing to ZCryptobyte?
	err = readASN1BigIntegerAsBytes(data, (*big.Int)(parsed))
	return err
}

func ParseSerialNumber(in zcryptobyte.String) (parsed *CertificateSerialNumber, raw zcryptobyte.String, err error) {
	var v CertificateSerialNumber
	err = parseSerialNumber(&in, &raw, &v)
	return &v, raw, err
}

// AlgorithmIdentifier holds the RFC 5280 SEQUENCE AlgorithmIdentifier, which
// consists of an OID and an optional set of opaque parameters.
//
//	AlgorithmIdentifier  ::=  SEQUENCE  {
//	  algorithm               OBJECT IDENTIFIER,
//	  parameters              ANY DEFINED BY algorithm OPTIONAL  }
type AlgorithmIdentifier struct {
	ObjectIdentifier encoding_asn1.ObjectIdentifier
	Parameters       Parameters
}

func parseAlgorithmIdentifier(in *zcryptobyte.String, out *zcryptobyte.String, parsed *AlgorithmIdentifier) (err error) {
	var seq zcryptobyte.String
	var tag asn1.Tag
	_, err = in.ReadAnyASN1(out, nil, &seq, &tag)
	if err != nil {
		return err
	}
	var oid zcryptobyte.String
	var rawOid zcryptobyte.String
	err = seq.ReadObjectIdentifier(&oid, &rawOid, &parsed.ObjectIdentifier)
	if err != nil {
		return err
	}
	// TODO(dadrian)[2024-10-27]: Parse Parameters
	return nil
}

func parseName(in *zcryptobyte.String, out *zcryptobyte.String, parsed *Name) (err error) {
	// TODO
	return
}

func parseValidity(in *zcryptobyte.String, out *zcryptobyte.String, parsed *Validity) (err error) {
	// TODO
	return
}

func parseSubjectPublicKeyInfo(in *zcryptobyte.String, out *zcryptobyte.String, parsed *SubjectPublicKeyInfo) (err error) {
	// TODO
	return
}

func parseUniqueID(in *zcryptobyte.String, out *zcryptobyte.String, parsed *UniqueIdentifier) (err error) {
	// TODO
	return
}

func parseExtensions(in *zcryptobyte.String, out *zcryptobyte.String, parsed *Extensions) (err error) {
	// TODO
	return
}

type BitString []byte
type CertificateSerialNumber big.Int
type Name []byte
type Validity []byte
type SubjectPublicKeyInfo []byte
type UniqueIdentifier []byte
type Extensions []byte
type ObjectIdentifier []byte
type Parameters []byte
