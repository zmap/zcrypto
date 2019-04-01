/*
 * ZCrypto Copyright 2019 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zcrypto

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
)

// Fingerprint represents a digest/fingerprint of some data. It can
// easily be encoded to hex and JSON (as a hex string).
type Fingerprint []byte

// CertificateFingerprint is an alias for Fingerprint when used specifically
// with certificates.
type CertificateFingerprint Fingerprint

// MD5Fingerprint creates a fingerprint of data using the MD5 hash algorithm.
func MD5Fingerprint(data []byte) Fingerprint {
	sum := md5.Sum(data)
	return sum[:]
}

// SHA1Fingerprint creates a fingerprint of data using the SHA1 hash algorithm.
func SHA1Fingerprint(data []byte) Fingerprint {
	sum := sha1.Sum(data)
	return sum[:]
}

// SHA256Fingerprint creates a fingerprint of data using the SHA256 hash
// algorithm.
func SHA256Fingerprint(data []byte) Fingerprint {
	sum := sha256.Sum256(data)
	return sum[:]
}

// SHA512Fingerprint creates a fingerprint of data using the SHA256 hash
// algorithm.
func SHA512Fingerprint(data []byte) Fingerprint {
	sum := sha512.Sum512(data)
	return sum[:]
}

// Equal returns true if the fingerprints are bytewise-equal.
func (f Fingerprint) Equal(other Fingerprint) bool {
	return bytes.Equal(f, other)
}

// Hex returns the given fingerprint encoded as a hex string.
func (f Fingerprint) Hex() string {
	return hex.EncodeToString(f)
}

// MarshalJSON implements the json.Marshaler interface, and marshals the
// fingerprint as a hex string.
func (f *Fingerprint) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Hex())
}
