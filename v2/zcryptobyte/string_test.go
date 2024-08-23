package zcryptobyte

import (
	"encoding/hex"
	"testing"

	"gotest.tools/assert"
)

func TestReadAnyASN1(t *testing.T) {
	var inputHex = "301a3018a003020102021100c71e983fe9f9fc9ece65efe1cae3857e"
	der, err := hex.DecodeString(inputHex)
	assert.NilError(t, err)

	t.Run("no outputs", func(t *testing.T) {
		s := String(der)
		n, err := s.ReadAnyASN1(nil, nil, nil, nil)
		assert.NilError(t, err)
		assert.Equal(t, len(der), int(n))
		assert.Equal(t, int(0), len(s))
	})
	t.Run("out", func(t *testing.T) {
		s := String(der)
		out := String{}
		n, err := s.ReadAnyASN1(&out, nil, nil, nil)
		assert.NilError(t, err)
		assert.Equal(t, int(0), len(s))
		assert.Equal(t, len(der), int(n))
		assert.Equal(t, len(der), len(out))
		assert.DeepEqual(t, String(der), out)
	})
	t.Run("header", func(t *testing.T) {
		s := String(der)
		header := String{}
		n, err := s.ReadAnyASN1(nil, &header, nil, nil)
		assert.NilError(t, err)
		assert.Equal(t, int(0), len(s))
		assert.Equal(t, len(der), int(n))
		assert.Equal(t, int(2), len(header))
		assert.DeepEqual(t, String(der[:2]), header)
	})
	t.Run("data", func(t *testing.T) {
		s := String(der)
		data := String{}
		n, err := s.ReadAnyASN1(nil, nil, &data, nil)
		assert.NilError(t, err)
		assert.Equal(t, len(der), int(n))
		assert.Equal(t, len(der)-2, len(data))
	})

}
