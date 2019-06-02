// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package tls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// This file added by ZCrypto.

// PointFormat is for TLS 1.2, and stores TLS Elliptic Curve Point Formats.
type PointFormat uint8

// MarshalJSON implements the json.Marshaler interface.
func (pFormat *PointFormat) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = byte(*pFormat)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  pFormat.String(),
		Value: uint8(*pFormat),
	}

	return json.Marshal(aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (pFormat *PointFormat) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForPointFormat(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched point format and name, point format: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*pFormat = PointFormat(aux.Value)
	return nil
}
