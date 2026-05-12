/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
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

package json

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
)

// RSAPublicKey provides JSON methods for the standard rsa.PublicKey.
// ZCrypto - bigE is set (and takes precedence over PublicKey.E) when the
// exponent does not fit in a Go int, e.g. for certs parsed by zcrypto's
// x509 package where E is a *big.Int.
type RSAPublicKey struct {
	*rsa.PublicKey
	// ZCrypto - full exponent for keys with E > max(int)
	bigE *big.Int
}

// ZCrypto - NewZRSAPublicKey creates an RSAPublicKey from a (N, E *big.Int)
// pair, preserving the full exponent value for JSON serialization.
func NewZRSAPublicKey(n, e *big.Int) *RSAPublicKey {
	stdKey := &rsa.PublicKey{N: n}
	if e != nil && e.IsInt64() {
		if e64 := e.Int64(); int64(int(e64)) == e64 {
			stdKey.E = int(e64)
		}
	}
	return &RSAPublicKey{PublicKey: stdKey, bigE: e}
}

// ZCrypto - auxRSAPublicKey uses json.Number for the exponent so that
// arbitrarily large values can be marshaled as JSON integers (not strings).
// Original: Exponent int
type auxRSAPublicKey struct {
	Exponent json.Number `json:"exponent"`
	Modulus  []byte      `json:"modulus"`
	Length   int         `json:"length"`
}

// RSAClientParams are the TLS key exchange parameters for RSA keys.
type RSAClientParams struct {
	Length       uint16 `json:"length,omitempty"`
	EncryptedPMS []byte `json:"encrypted_pre_master_secret,omitempty"`
}

// MarshalJSON implements the json.Marshal interface
func (rp *RSAPublicKey) MarshalJSON() ([]byte, error) {
	var aux auxRSAPublicKey
	if rp.PublicKey != nil {
		// ZCrypto - use bigE when present (full precision); fall back to int E.
		// Original: aux.Exponent = rp.E (int)
		if rp.bigE != nil {
			aux.Exponent = json.Number(rp.bigE.String())
		} else {
			aux.Exponent = json.Number(strconv.Itoa(rp.E))
		}
		aux.Modulus = rp.N.Bytes()
		aux.Length = len(aux.Modulus) * 8
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshal interface
func (rp *RSAPublicKey) UnmarshalJSON(b []byte) error {
	var aux auxRSAPublicKey
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if rp.PublicKey == nil {
		rp.PublicKey = new(rsa.PublicKey)
	}
	// ZCrypto - parse exponent via big.Int to handle values larger than int.
	// Only store bigE for exponents that don't fit in a plain int; for normal
	// exponents just set E on the embedded rsa.PublicKey (preserves round-trip
	// equality with keys created without bigE).
	// Original: rp.E = aux.Exponent (direct int assignment)
	bigE, ok := new(big.Int).SetString(string(aux.Exponent), 10)
	if ok {
		if bigE.IsInt64() {
			if e64 := bigE.Int64(); int64(int(e64)) == e64 {
				rp.E = int(e64)
			} else {
				rp.bigE = bigE
			}
		} else {
			rp.bigE = bigE
		}
	}
	rp.N = big.NewInt(0).SetBytes(aux.Modulus)
	if len(aux.Modulus)*8 != aux.Length {
		return fmt.Errorf("mismatched length (got %d, field specified %d)", len(aux.Modulus), aux.Length)
	}
	return nil
}

// BigE returns the exponent as a *big.Int, regardless of size.
// ZCrypto - added to expose the full exponent value.
func (rp *RSAPublicKey) BigE() *big.Int {
	if rp.bigE != nil {
		return rp.bigE
	}
	if rp.PublicKey != nil {
		return big.NewInt(int64(rp.E))
	}
	return nil
}
