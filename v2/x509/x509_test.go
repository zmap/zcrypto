package x509

import (
	"fmt"
	"os"
	"path"
	"testing"

	"gopkg.in/yaml.v3"
	"gotest.tools/assert"
)

type Manifest struct {
	Certificates []CertificateTestCase `yaml:"certificates"`
}

type CertificateTestCase struct {
	Name      string `yaml:"name"`
	SHA256Hex string `yaml:"sha256"`
}

func TestParseReal(t *testing.T) {
	manifestBytes, err := os.ReadFile("testdata/certificates.yaml")
	assert.NilError(t, err)

	var manifest Manifest
	err = yaml.Unmarshal(manifestBytes, &manifest)
	assert.NilError(t, err)

	for i, testcase := range manifest.Certificates {
		t.Run(fmt.Sprintf("%2d-%s", i, testcase.Name), func(t *testing.T) {
			b, err := os.ReadFile(path.Join("testdata", testcase.Name))
			assert.NilError(t, err)
			c, err := ParseCertificate(b)
			assert.NilError(t, err)
			assert.Check(t, len(c.RawTBSCertificate) > 0)
			assert.Check(t, len(c.RawSignatureAlgorithm) > 0)
			assert.Check(t, len(c.RawSignature) > 0)
		})
	}
}
