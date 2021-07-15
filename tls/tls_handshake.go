// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type TLSVersion uint16

type CompressionMethod uint8

func (cm *CompressionMethod) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = byte(*cm)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  cm.String(),
		Value: uint8(*cm),
	}

	return json.Marshal(aux)
}

func (cm *CompressionMethod) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForCompressionMethod(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched compression method and name, compression method: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*cm = CompressionMethod(aux.Value)
	return nil
}
