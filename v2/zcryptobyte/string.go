// ZCrypto Copyright 2019 Regents of the University of Michigan
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy
// of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package zcryptobyte implements a version of cryptobyte that's easier to misuse
package zcryptobyte

import (
	"errors"

	"github.com/zmap/zcrypto/v2/zcryptobyte/asn1"
)

var ErrOverflow = errors.New("overflow in output buffer")
var ErrUnderflow = errors.New("underflow in input buffer")

// String represents an immutable set of bytes that can be consumed. Read
// functions will consume bytes by reassigning the slice forwards.
type String []byte

// read advances a String by n bytes and returns them. If less than n bytes
// remain, it returns nil.
func (s *String) read(n int) []byte {
	if len(*s) < n || n < 0 {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}

// ReadBytes reads n bytes into out and advances over them. It reports
// whether the read was successful.
func (s *String) ReadBytes(out *[]byte, n int) bool {
	v := s.read(n)
	if v == nil {
		return false
	}
	if out != nil {
		*out = v
	}
	return true
}

// Skip advances the String by n byte and reports whether it was successful.
func (s *String) Skip(n int) bool {
	return s.read(n) != nil
}

func (s *String) readUnsignedAs32(out *uint32, length int) bool {
	v := s.read(length)
	if v == nil {
		return false
	}
	var result uint32
	for i := 0; i < length; i++ {
		result <<= 8
		result |= uint32(v[i])
	}
	*out = result
	return true
}

func (s *String) ReadAnyASN1(out *String, header, data *String, tag *asn1.Tag) (n uint32, err error) {
	input := *s
	totalLen, headerLen, dataLen, err := s.readAnyASN1(out, tag)
	if err != nil {
		return totalLen, err
	}
	if header != nil {
		*header = input[0:headerLen]
	}
	if data != nil {
		*data = input[headerLen : headerLen+dataLen]
	}
	return totalLen, nil
}

func (s *String) ReadTaggedASN1(out *String, data *String, tag asn1.Tag) (n uint32, err error) {
	var actual asn1.Tag
	totalLen, headerLen, dataLen, err := s.readAnyASN1(out, &actual)
	if err != nil {
		return totalLen, err
	}
	if actual != tag {
		return totalLen, asn1.MismatchedTag(tag, actual)
	}
	*data = (*out)[headerLen : headerLen+dataLen]
	return totalLen, nil
}

func (s *String) readAnyASN1(out *String, outTag *asn1.Tag) (totalLen, headerLen, dataLen uint32, err error) {
	if len(*s) < 2 {
		return 0, 0, 0, asn1.ErrHeaderUnderflow
	}

	tag, lenByte := (*s)[0], (*s)[1]

	if tag&0x1f == 0x1f {
		// ITU-T X.690 section 8.1.2
		//
		// An identifier octet with a tag part of 0x1f indicates a high-tag-number
		// form identifier with two or more octets. We only support tags less than
		// 31 (i.e. low-tag-number form, single octet identifier).
		//
		// This behavior is carried over from cryptobyte
		return 0, 0, 0, asn1.ErrMultiByteTag
	}

	// Save the output tag
	if outTag != nil {
		*outTag = asn1.Tag(tag)
	}

	// ITU-T X.690 section 8.1.3
	//
	// Bit 8 of the first length byte indicates whether the length is short- or
	// long-form.
	//
	// The encoded length does not include the length of the header.
	if lenByte&0x80 == 0 {
		// Short-form length (section 8.1.3.4), encoded in bits 1-7.
		dataLen = uint32(lenByte)
		headerLen = 2
	} else {
		// Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
		// used to encode the length of the length field.
		lenLen := lenByte & 0x7f

		if lenLen == 0 {
			return 0, 0, 0, asn1.ErrLengthUnderflow
		}

		if lenLen > 4 {
			return 0, 0, 0, asn1.ErrLengthOverflow
		}

		if len(*s) < int(2+lenLen) {
			return 0, 0, 0, asn1.ErrHeaderUnderflow
		}

		var len32 uint32
		lenBytes := String((*s)[2 : 2+lenLen])
		if !lenBytes.readUnsignedAs32(&len32, int(lenLen)) {
			return 0, 0, 0, asn1.ErrHeaderUnderflow
		}

		// TODO(dadrian)[2024-08-04]: We probably want to capture all of this
		// information somehow. Or at least expose it via a function that e.g.
		// an ASN.1 linter could call.
		//
		// // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
		// // with the minimum number of octets.
		// if len32 < 128 {
		// 	// Length should have used short-form encoding.
		// 	return false
		// }
		// if len32>>((lenLen-1)*8) == 0 {
		// 	// Leading octet is 0. Length should have been at least one byte shorter.
		// 	return false
		// }

		dataLen = len32
		headerLen = 2 + uint32(lenLen)
		if headerLen+dataLen < len32 {
			// Overflow.
			return 0, 0, 0, ErrOverflow
		}
	}
	totalLen = dataLen + headerLen

	if int(totalLen) < 0 {
		return 0, 0, 0, ErrOverflow
	}

	if !s.ReadBytes((*[]byte)(out), int(totalLen)) {
		return 0, 0, 0, ErrUnderflow
	}
	return
}
