package pem

import (
	stdlib_pem "encoding/pem"
	"errors"
)

var ErrInvalidPEM = errors.New("invalid PEM")

func DecodeContents(b []byte) ([]byte, error) {
	block, _ := stdlib_pem.Decode(b)
	if block == nil {
		return nil, ErrInvalidPEM
	}
	return block.Bytes, nil
}
