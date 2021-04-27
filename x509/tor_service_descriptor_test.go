package x509

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

// TestParseTorServiceDescriptorSyntax tests that parsing certificates with the
// CAB Forum TorServiceDescriptorSyntax x509 extension works correctly.
func TestParseTorServiceDescriptorSyntax(t *testing.T) {
	// expected TorServiceDescriptorHash hash bytes from test certs.
	mockHashBytes := []byte{
		0xc7, 0x49, 0xf5, 0xb2, 0x49, 0x9c, 0x8f, 0x65,
		0x5c, 0x19, 0xb3, 0x3f, 0xf9, 0x3e, 0x03, 0x7b,
		0x7b, 0x7d, 0xbe, 0x47, 0x2a, 0xac, 0x62, 0x78,
		0x30, 0x71, 0xb0, 0x39, 0xb8, 0x66, 0x38, 0x5c,
	}
	mockAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
	}
	// mustASN1 marshals a given object to its ASN1 bytes or panics.
	mustASN1 := func(value interface{}) []byte {
		result, err := asn1.Marshal(value)
		if err != nil {
			panic(fmt.Sprintf("err marshaling asn1 test data: %v", err))
		}
		return result
	}
	// sequence marshals a ASN1 SEQUENCE for the given bytes.
	sequence := func(bytes []byte) []byte {
		return mustASN1(asn1.RawValue{
			Tag:        asn1.TagSequence,
			Class:      asn1.ClassUniversal,
			IsCompound: true,
			Bytes:      bytes,
		})
	}
	// torServiceDescriptorHash constructs a marshaled SEQUENCE for
	// a TorServiceDescriptorHash with the given values.
	torServiceDescriptorHash := func(onion string, algorithm pkix.AlgorithmIdentifier, hash []byte, bits int) []byte {
		return sequence(
			append(mustASN1(asn1.RawValue{
				Tag:   asn1.TagUTF8String,
				Class: asn1.ClassUniversal,
				Bytes: []byte(onion),
			}),
				append(
					mustASN1(algorithm),
					mustASN1(asn1.BitString{
						Bytes:     hash,
						BitLength: bits,
					})...)...,
			))
	}
	testCases := []struct {
		Name                          string
		InputExtension                pkix.Extension
		ExpectedErrMsg                string
		ExpectedTorServiceDescriptors []*TorServiceDescriptorHash
	}{
		{
			Name: "empty Tor service descriptor extension",
			InputExtension: pkix.Extension{
				Value: nil,
			},
			ExpectedErrMsg: "asn1: syntax error: unable to unmarshal outer TorServiceDescriptor SEQUENCE",
		},
		{
			Name: "invalid outer SEQUENCE in service descriptor extension",
			InputExtension: pkix.Extension{
				Value: mustASN1(asn1.RawValue{}),
			},
			ExpectedErrMsg: "asn1: syntax error: invalid outer TorServiceDescriptor SEQUENCE",
		},
		{
			Name: "data trailing outer SEQUENCE in service descriptor extension",
			InputExtension: pkix.Extension{
				Value: append(
					sequence(nil),                // Outer SEQUENCE
					mustASN1(asn1.RawValue{})..., // Trailing data
				),
			},
			ExpectedErrMsg: "asn1: syntax error: trailing data after outer TorServiceDescriptor SEQUENCE",
		},
		{
			Name: "bad service descriptor onion URI field tag",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					sequence( // TorServiceDescriptorHash SEQUENCE
						mustASN1(asn1.RawValue{}), // Invalid Onion URI
					)),
			},
			ExpectedErrMsg: "asn1: syntax error: TorServiceDescriptorHash missing non-compound UTF8String tag",
		},
		{
			Name: "bad service descriptor algorithm field",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					sequence( // TorServiceDescriptorHash SEQUENCE
						mustASN1(asn1.RawValue{ // Onion URI
							Tag:   asn1.TagUTF8String,
							Class: asn1.ClassUniversal,
						}))),
				// No pkix.AlgorithmIdentifier algorithm field
			},
			ExpectedErrMsg: "asn1: syntax error: error unmarshaling TorServiceDescriptorHash algorithm",
		},
		{
			Name: "bad service descriptor hash field",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					sequence( // TorServiceDescriptorHash SEQUENCE
						append(mustASN1(asn1.RawValue{ // Onion URI
							Tag:   asn1.TagUTF8String,
							Class: asn1.ClassUniversal,
						}),
							mustASN1(mockAlgorithm)...), // Algorithm
					)),
				// No BitString hash field
			},
			ExpectedErrMsg: "asn1: syntax error: error unmarshaling TorServiceDescriptorHash Hash",
		},
		{
			Name: "data trailing inner TorServiceDescriptorHash SEQUENCE",
			InputExtension: pkix.Extension{
				Value: sequence(
					sequence( // Outer SEQUENCE
						append(mustASN1(asn1.RawValue{ // Onion URI
							Tag:   asn1.TagUTF8String,
							Class: asn1.ClassUniversal,
						}),
							append(
								append(
									mustASN1(mockAlgorithm), // Algorithm
									mustASN1(asn1.BitString{ // Hash
										Bytes:     []byte{0x00},
										BitLength: 1,
									})...,
								),
								mustASN1(asn1.RawValue{})..., // Trailing data
							)...,
						),
					)),
			},
			ExpectedErrMsg: "asn1: syntax error: trailing data after TorServiceDescriptorHash",
		},
		{
			Name: "valid service descriptor unknown hash algorithm",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					torServiceDescriptorHash(
						"https://zmap.onion",
						pkix.AlgorithmIdentifier{
							Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 99},
						},
						mockHashBytes,
						256),
				),
			},
			ExpectedTorServiceDescriptors: []*TorServiceDescriptorHash{
				{
					Onion:         "https://zmap.onion",
					AlgorithmName: "Unknown",
					Algorithm: pkix.AlgorithmIdentifier{
						Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 99},
					},
					HashBits: 256,
					Hash:     mockHashBytes,
				},
			},
		},
		{
			Name: "valid service descriptor extension",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					torServiceDescriptorHash(
						"https://zmap.onion",
						mockAlgorithm,
						mockHashBytes,
						256),
				)},
			ExpectedTorServiceDescriptors: []*TorServiceDescriptorHash{
				{
					Onion:         "https://zmap.onion",
					AlgorithmName: "SHA256",
					Algorithm:     mockAlgorithm,
					HashBits:      256,
					Hash:          mockHashBytes,
				},
			},
		},
		{
			Name: "valid service descriptor extension, multiple entries",
			InputExtension: pkix.Extension{
				Value: sequence( // Outer SEQUENCE
					append(torServiceDescriptorHash(
						"https://zmap.onion",
						mockAlgorithm,
						mockHashBytes,
						256),
						torServiceDescriptorHash(
							"https://other.onion",
							mockAlgorithm,
							mockHashBytes,
							256)...),
				)},
			ExpectedTorServiceDescriptors: []*TorServiceDescriptorHash{
				{
					Onion:         "https://zmap.onion",
					AlgorithmName: "SHA256",
					Algorithm:     mockAlgorithm,
					HashBits:      256,
					Hash:          mockHashBytes,
				},
				{
					Onion:         "https://other.onion",
					AlgorithmName: "SHA256",
					Algorithm:     mockAlgorithm,
					HashBits:      256,
					Hash:          mockHashBytes,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			descs, err := parseTorServiceDescriptorSyntax(tc.InputExtension)
			if err != nil && tc.ExpectedErrMsg == "" {
				t.Errorf("expected no error, got %v", err)
			} else if err == nil && tc.ExpectedErrMsg != "" {
				t.Errorf("expected error %q, got nil", tc.ExpectedErrMsg)
			} else if err != nil && err.Error() != tc.ExpectedErrMsg {
				t.Errorf("expected error %q, got %q", tc.ExpectedErrMsg, err.Error())
			} else if err == nil && tc.ExpectedErrMsg == "" {
				if len(descs) != len(tc.ExpectedTorServiceDescriptors) {
					t.Errorf("expected %d TorServiceDescriptorHashes, got %d",
						len(tc.ExpectedTorServiceDescriptors), len(descs))
				}
				for i, servDesc := range descs {
					if !reflect.DeepEqual(servDesc, tc.ExpectedTorServiceDescriptors[i]) {
						t.Errorf("expected TorServiceDescriptors %#v in index %d, got %#v",
							tc.ExpectedTorServiceDescriptors[i], i, servDesc)
					}
				}
			}
		})
	}
}
