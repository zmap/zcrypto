package x509

import (
	"fmt"
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/zmap/zcrypto/v2/pem"
	"github.com/zmap/zcrypto/v2/pkg/must"
	"github.com/zmap/zcrypto/v2/zcryptobyte"
	"golang.org/x/crypto/cryptobyte"
	"gopkg.in/yaml.v3"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

type Manifest struct {
	Certificates []CertificateTestCase `yaml:"certificates"`
}

type CertificateTestCase struct {
	Name            string `yaml:"name"`
	SHA256Hex       string `yaml:"sha256"`
	RawVersion      string `yaml:"RawVersion"`
	RawSerialNumber string `yaml:"RawSerialNumber"`
}

func TestParseReal(t *testing.T) {
	manifestBytes, err := os.ReadFile("testdata/certificates.yaml")
	assert.NilError(t, err)

	var manifest Manifest
	err = yaml.Unmarshal(manifestBytes, &manifest)
	assert.NilError(t, err)

	for i, testcase := range manifest.Certificates {
		t.Run(fmt.Sprintf("%2d-%s", i, testcase.Name), func(t *testing.T) {
			pemBytes, err := os.ReadFile(path.Join("testdata", testcase.Name))
			assert.NilError(t, err)
			b, err := pem.DecodeContents(pemBytes)
			assert.NilError(t, err)
			n, c, err := ParseCertificate(b)
			assert.NilError(t, err)

			assert.Check(t, len(c.RawTBSCertificate) > 0)
			assert.Check(t, len(c.RawSignatureAlgorithm) > 0)
			assert.Check(t, len(c.RawSignature) > 0)
			assert.Check(t, cmp.Equal(uint32(len(b)), n))

			// The certificate should have a 4 byte "prefix" describing the core
			// SEQUENCE, so the sum of the remaining lengths should be 4 less
			// than the total length.
			totalRawLen := len(c.RawTBSCertificate) + len(c.RawSignatureAlgorithm) + len(c.RawSignature)
			assert.Check(t, cmp.Equal(len(b)-4, totalRawLen))

			if testcase.RawVersion != "" {
				assert.DeepEqual(t, must.HexDecodeString(testcase.RawVersion), []byte(c.TBSCertificate.RawVersion))
			}
			if testcase.RawSerialNumber != "" {
				assert.DeepEqual(t, must.HexDecodeString(testcase.RawSerialNumber), []byte(c.TBSCertificate.RawSerialNumber))
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	standardVersions := []int64{0, 1, 5}
	for i, v := range standardVersions {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			var buf [3]byte
			// TODO(dadrian)[2024-10-22]: This should use zcryptobyte, not cryptobyte.
			b := cryptobyte.NewBuilder(buf[:0])
			b.AddASN1Int64WithTag(v, 0)
			enc := b.BytesOrPanic()
			v, raw, err := ParseVersion(enc)
			assert.NilError(t, err, "ParseVersion(%X) returned an error %s", enc, err)
			assert.Check(t, cmp.DeepEqual(raw, zcryptobyte.String(enc)))
			assert.Check(t, cmp.Equal(*v, standardVersions[i]))
		})
	}
}

func TestParseSerialNumber(t *testing.T) {
	numbers := []*big.Int{big.NewInt(-1), big.NewInt(42), big.NewInt(20231201)}
	for i, v := range numbers {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			var buf [9]byte
			// TODO(dadrian)[2024-10-22]: This should use zcryptobyte, not cryptobyte.
			b := cryptobyte.NewBuilder(buf[:0])
			b.AddASN1BigInt(v)
			enc := b.BytesOrPanic()
			serial, raw, err := ParseSerialNumber(enc)
			assert.NilError(t, err, "ParserSerialNumber(%X) returned an error %s", enc, err)
			assert.Check(t, cmp.DeepEqual(raw, zcryptobyte.String(enc)))
			assert.Check(t, cmp.Equal((*big.Int)(serial).Cmp(v), 0))
		})
	}
}
