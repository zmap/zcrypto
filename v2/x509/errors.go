package x509

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type InvalidASN1Error struct {
	Reason           InvalidASN1Reason
	fieldName        string
	expected, actual interface{}

	underlying error
}

func InvalidASN1(fieldName string, underlying error) error {
	return InvalidASN1Error{
		fieldName:  fieldName,
		underlying: underlying,
	}
}

func MismatchedTagIn(expected asn1.Tag, in cryptobyte.String) error {
	var actual interface{}
	if len(in) > 0 {
		actual = in[0]
	}
	return InvalidASN1Error{
		Reason:   ReasonMismatchedTag,
		expected: expected,
		actual:   actual,
	}
}

func (e InvalidASN1Error) Error() string {
	if e.underlying != nil {
		return fmt.Sprintf("%s: %s", e.Reason, e.underlying)
	}
	if e.expected != nil {
		return fmt.Sprintf("%s: expected %v, got %v", e.Reason, e.expected, e.actual)
	}
	return fmt.Sprintf("%s", e.Reason)
}

//go:generate stringer -type=InvalidASN1Reason -trimprefix=Reason
type InvalidASN1Reason int

const (
	ReasonUnknown         InvalidASN1Reason = 0
	ReasonInvalidInteger  InvalidASN1Reason = 1
	ReasonMismatchedTag   InvalidASN1Reason = 2
	ReasonInvalidSequence InvalidASN1Reason = 3 // TODO(dadrian): This should be a mismatched tag or something else
)
