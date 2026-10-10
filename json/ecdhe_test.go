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
	"crypto/rand"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestEncodeDecodeCurveID(t *testing.T) {
	for curve := range ecIDToName {
		out, err := json.Marshal(&curve)
		if err != nil {
			t.Fatal(err)
		}

		var back TLSCurveID
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatal(err)
		}
		if back != curve {
			t.Errorf("decoded curve: got %v, want %v", back, curve)
		}
	}
}

func TestEncodeDecodeECPoint(t *testing.T) {
	maxCoordinate := new(big.Int)
	maxCoordinate.Exp(big.NewInt(2), big.NewInt(255), nil)
	maxCoordinate.Sub(maxCoordinate, big.NewInt(19))

	x, err := rand.Int(rand.Reader, maxCoordinate)
	if err != nil {
		t.Fatal(err)
	}
	y, err := rand.Int(rand.Reader, maxCoordinate)
	if err != nil {
		t.Fatal(err)
	}

	p := ECPoint{
		X: x,
		Y: y,
	}
	out, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}

	var back ECPoint
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
}

func TestCurveIDDescription(t *testing.T) {
	for curve, name := range ecIDToName {
		if got := curve.Description(); got != name {
			t.Errorf("curve %v: got description %q, want %q", curve, got, name)
		}
	}

	unk := TLSCurveID(6500)
	if got := unk.Description(); got != "unknown" {
		t.Errorf("unknown curve: got description %q, want %q", got, "unknown")
	}
}

func TestEncodeDecodeECParam(t *testing.T) {
	ecp := new(ECDHParams)
	out, err := json.Marshal(ecp)
	if err != nil {
		t.Fatal(err)
	}

	back := new(ECDHParams)
	if err := json.Unmarshal(out, back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, ecp) {
		t.Errorf("decoded params: got %+v, want %+v", back, ecp)
	}
}
