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

// Package asn1 contains constants related to parsing ASN.1 with zcryptobyte
package asn1

import (
	"errors"
	"fmt"
)

type Tag uint8

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80
)

var ErrHeaderUnderflow = errors.New("underflow in header (missing header bytes)")
var ErrMultiByteTag = errors.New("multibyte tags are unsupported")
var ErrUnderflow = errors.New("underflow, missing data bytes")

var ErrLengthUnderflow = errors.New("underflow in length of length")
var ErrLengthOverflow = errors.New("greater than 4-byte length")

var ErrInvalidInteger = errors.New("greater than 4-byte integer")

type MismatchedTagError struct {
	Expected Tag
	Actual   Tag
}

func (e MismatchedTagError) Error() string {
	return fmt.Sprintf("mismatched tags: expected %02x, got %02x", e.Expected, e.Actual)
}

func MismatchedTag(expected, actual Tag) error {
	return MismatchedTagError{
		Expected: expected,
		Actual:   actual,
	}
}

const (
	BOOLEAN           = Tag(1)
	INTEGER           = Tag(2)
	BIT_STRING        = Tag(3)
	OCTET_STRING      = Tag(4)
	NULL              = Tag(5)
	OBJECT_IDENTIFIER = Tag(6)
	ENUM              = Tag(10)
	UTF8String        = Tag(12)
	SEQUENCE          = Tag(16 | classConstructed)
	SET               = Tag(17 | classConstructed)
	PrintableString   = Tag(19)
	T61String         = Tag(20)
	IA5String         = Tag(22)
	UTCTime           = Tag(23)
	GeneralizedTime   = Tag(24)
	GeneralString     = Tag(27)
)
