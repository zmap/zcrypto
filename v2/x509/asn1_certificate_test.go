package x509

import (
	"encoding/pem"
	"testing"

	"github.com/zmap/zcrypto/data/test/certificates"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestREPL(t *testing.T) {
	inPem := certificates.PEMDAdrianIOSignedByLEX3
	b, _ := pem.Decode([]byte(inPem))
	c, err := ParseASN1Certificate(b.Bytes)
	t.Logf("%v", c == nil)
	t.Logf("%v", err)
	t.Fail()
}

func TestCryptobyteReadIntoSelf(t *testing.T) {
	inPem := certificates.PEMDAdrianIOSignedByLEX3
	b, _ := pem.Decode([]byte(inPem))
	full := cryptobyte.String(b.Bytes)
	t.Errorf("len(full) = %d", len(full))
	t.Errorf("&full = %p", &full)
	t.Errorf("&full[4] = %p", &full[4])
	var out cryptobyte.String
	full.ReadASN1(&out, asn1.SEQUENCE)
	t.Errorf("&full = %p", &full)
	t.Errorf("&out[0] = %p", &out[0])
	t.Errorf("len(full) = %d", len(full))
	t.Errorf("len(out) = %d", len(out))
}
