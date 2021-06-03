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
		legacy   string
	}{
		{
			name:     Name{},
			expected: "",
			legacy:   "",
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
			expected: "serialNumber=67890, CN=name, serialNumber=12345, C=US, C=RU, postalCode=48109, ST=Michigan, L=Ann Arbor, street=2260 Hayward St, O=University of Michigan, OU=0x21, CN=common",
			legacy:   "CN=common, OU=0x21, O=University of Michigan, street=2260 Hayward St, L=Ann Arbor, ST=Michigan, postalCode=48109, C=US, C=RU, serialNumber=12345, CN=name, serialNumber=67890",
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
						{Type: oidGivenName, Value: "given"},
						{Type: oidDomainComponent, Value: "domain"},
						{Type: oidDNEmailAddress, Value: "user@dn.com"},
						{Type: oidJurisdictionLocality, Value: "Locality"},
						{Type: oidJurisdictionProvince, Value: "Prov"},
						{Type: oidJurisdictionCountry, Value: "Canada"},
						{Type: oidOrganizationID, Value: "QWACS"},
					},
				},
			},
			expected: "postalCode=48109, serialNumber=12345, CN=common, GN=given, DC=domain, emailAddress=user@dn.com, jurisdictionLocality=Locality, jurisdictionStateOrProvince=Prov, jurisdictionCountry=Canada, organizationIdentifier=QWACS",
			legacy:   "postalCode=48109, serialNumber=12345, CN=common, GN=given, DC=domain, emailAddress=user@dn.com, jurisdictionLocality=Locality, jurisdictionStateOrProvince=Prov, jurisdictionCountry=Canada, organizationIdentifier=QWACS",
		},
	}
	for _, test := range tests {
		s := test.name.String()
		assert.Equal(t, test.expected, s)
	}
	LegacyNameString = true
	for _, test := range tests {
		s := test.name.String()
		assert.Equal(t, test.legacy, s)
	}
}
