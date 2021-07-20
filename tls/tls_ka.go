// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"regexp"
	"strconv"
)

// SignatureAndHash is a SigAndHash that implements json.Marshaler and
// json.Unmarshaler
type SignatureAndHash SigAndHash

type auxSignatureAndHash struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
}

// MarshalJSON implements the json.Marshaler interface
func (sh *SignatureAndHash) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAndHash{
		SignatureAlgorithm: nameForSignature(sh.Signature),
		HashAlgorithm:      nameForHash(sh.Hash),
	}
	return json.Marshal(&aux)
}

var unknownAlgorithmRegex = regexp.MustCompile(`unknown\.(\d+)`)

// UnmarshalJSON implements the json.Unmarshaler interface
func (sh *SignatureAndHash) UnmarshalJSON(b []byte) error {
	aux := new(auxSignatureAndHash)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	sh.Signature = signatureToName(aux.SignatureAlgorithm)
	sh.Hash = hashToName(aux.HashAlgorithm)
	return nil
}

// DigitalSignature represents a signature for a digitally-signed-struct in the
// TLS record protocol. It is dependent on the version of TLS in use. In TLS
// 1.2, the first two bytes of the signature specify the signature and hash
// algorithms. These are contained the TLSSignature.Raw field, but also parsed
// out into TLSSignature.SigHashExtension. In older versions of TLS, the
// signature and hash extension is not used, and so
// TLSSignature.SigHashExtension will be empty. The version string is stored in
// TLSSignature.TLSVersion.
type DigitalSignature struct {
	Raw              []byte            `json:"raw"`
	Type             string            `json:"type,omitempty"`
	Valid            bool              `json:"valid"`
	SigHashExtension *SignatureAndHash `json:"signature_and_hash_type,omitempty"`
	Version          TLSVersion        `json:"tls_version"`
}

func signatureTypeToName(sigType uint8) string {
	switch sigType {
	case signatureRSA:
		return "rsa"
	case signatureDSA:
		return "dsa"
	case signatureECDSA:
		return "ecdsa"
	default:
		break
	}
	return "unknown." + strconv.Itoa(int(sigType))
}
