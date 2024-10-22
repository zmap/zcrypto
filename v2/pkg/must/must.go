package must

import "encoding/hex"

// HexDecodeString decodes the input as a hex string, or panics.
func HexDecodeString(in string) []byte {
	b, err := hex.DecodeString(in)
	if err != nil {
		panic(err.Error())
	}
	return b
}
