// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNameString(t *testing.T) {
	tests := []struct {
		name     Name
		expected string
	}{
		{
			name:     Name{},
			expected: "",
		},
		{
			name: Name{
				SerialNumber:       "12345",
				CommonName:         "common",
				Country:            []string{"US", "RU"},
				Organization:       []string{"University of Michigan"},
				OrganizationalUnit: []string{"0x21"},
				Locality:           []string{"Ann Arbor"},
				Province:           []string{"Michigan"},
				StreetAddress:      []string{"2260 Hayward St"},
				PostalCode:         []string{"48109"},
				DomainComponent:    nil,
				ExtraNames:         []AttributeTypeAndValue{{Type: oidCommonName, Value: "name"}, {Type: oidSerialNumber, Value: "67890"}},
			},
			expected: "SERIALNUMBER=67890, CN=name, SERIALNUMBER=12345, C=US, C=RU, POSTALCODE=48109, ST=Michigan, L=Ann Arbor, STREET=2260 Hayward St, O=University of Michigan, OU=0x21, CN=common",
		},
		{
			name: Name{
				SerialNumber: "12345",
				CommonName:   "common",
				PostalCode:   []string{"48109"},
				OriginalRDNS: RDNSequence{
					[]AttributeTypeAndValue{
						{Type: oidPostalCode, Value: "48109"},
						{Type: oidSerialNumber, Value: "12345"},
						{Type: oidCommonName, Value: "common"},
					},
				},
			},
			expected: "POSTALCODE=48109, SERIALNUMBER=12345, CN=common",
		},
	}
	for _, test := range tests {
		s := test.name.String()
		assert.Equal(t, test.expected, s)
	}
}
