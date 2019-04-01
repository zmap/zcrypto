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
	"encoding/json"
	"testing"
)

var randomData = []byte("somerandomdata")

type fpJSONTestStruct struct {
	FP Fingerprint `json:"fp"`
}

func TestMD5Fingerprint(t *testing.T) {
	fingerprint := MD5Fingerprint(randomData)
	if fingerprint.Hex() != "5698ed1e3d65a854fc702393fb2049b4" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"5698ed1e3d65a854fc702393fb2049b4"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA1Fingerprint(t *testing.T) {
	fingerprint := SHA1Fingerprint(randomData)

	if fingerprint.Hex() != "26f30f9a9ff52d1cfbd18c4ca4d54a898b05ce0d" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"26f30f9a9ff52d1cfbd18c4ca4d54a898b05ce0d"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA256Fingerprint(t *testing.T) {
	fingerprint := SHA256Fingerprint(randomData)

	if fingerprint.Hex() != "dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA512Fingerprint(t *testing.T) {
	fingerprint := SHA512Fingerprint(randomData)

	if fingerprint.Hex() != "4e8a382161e2ee2fe460cbf99a2df371a7ce3b2587a637a6c3cec91fa2920ab969b40e4c9ec12ef12405e175d0b09baf35a46c4349e658def41b6d296bad3fd2" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"4e8a382161e2ee2fe460cbf99a2df371a7ce3b2587a637a6c3cec91fa2920ab969b40e4c9ec12ef12405e175d0b09baf35a46c4349e658def41b6d296bad3fd2"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}
