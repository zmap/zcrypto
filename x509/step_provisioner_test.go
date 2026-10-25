package x509

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
)

// stepProvisionerTestCertificate builds a self-signed certificate carrying the
// Smallstep provisioner extension with the given contents, and returns it
// parsed by this package.
func stepProvisionerTestCertificate(t *testing.T, sp StepProvisioner) *Certificate {
	t.Helper()

	value, err := asn1.Marshal(sp)
	if err != nil {
		t.Fatalf("marshalling StepProvisioner: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := cryptox509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "step-provisioner.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}, Value: value},
		},
	}

	der, err := cryptox509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// TestParseStepProvisioner tests that the Smallstep step-ca provisioner
// extension is parsed out of a certificate rather than left unknown.
func TestParseStepProvisioner(t *testing.T) {
	cert := stepProvisionerTestCertificate(t, StepProvisioner{
		Type:          stepProvisionerACME,
		Name:          []byte("acme"),
		CredentialID:  []byte("cred-1"),
		KeyValuePairs: []string{"key", "value"},
	})

	if cert.StepProvisioner == nil {
		t.Fatal("expected StepProvisioner to be populated, got nil")
	}
	if got, want := cert.StepProvisioner.Type, stepProvisionerACME; got != want {
		t.Errorf("Type = %d, want %d", got, want)
	}
	if got, want := string(cert.StepProvisioner.Name), "acme"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if got, want := string(cert.StepProvisioner.CredentialID), "cred-1"; got != want {
		t.Errorf("CredentialID = %q, want %q", got, want)
	}

	// The extension should be reported as a known extension rather than
	// landing in the unknown bucket.
	exts, unknown := cert.JsonifyExtensions()
	if exts.StepProvisioner == nil {
		t.Error("expected CertificateExtensions.StepProvisioner to be populated")
	}
	for _, e := range unknown {
		if e.Id.Equal(oidExtStepProvisioner) {
			t.Error("provisioner extension was reported as unknown")
		}
	}
}

// TestStepProvisionerMarshalJSON tests the JSON rendering of the extension,
// including the mapping of the numeric provisioner type to its step-ca name
// and the expansion of the flat key/value list into an object.
func TestStepProvisionerMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   StepProvisioner
		want string
	}{
		{
			name: "known type with key value pairs",
			in: StepProvisioner{
				Type:          stepProvisionerJWK,
				Name:          []byte("admin"),
				CredentialID:  []byte("abc"),
				KeyValuePairs: []string{"k", "v"},
			},
			want: `{"type":"JWK","name":"admin","credential_id":"abc","key_value_pairs":{"k":"v"}}`,
		},
		{
			name: "credential id and pairs omitted when empty",
			in: StepProvisioner{
				Type: stepProvisionerNebula,
				Name: []byte("mesh"),
			},
			want: `{"type":"Nebula","name":"mesh"}`,
		},
		{
			name: "unknown type rendered with its value",
			in: StepProvisioner{
				Type: 99,
				Name: []byte("future"),
			},
			want: `{"type":"unknown (99)","name":"future"}`,
		},
		{
			name: "trailing key without a value",
			in: StepProvisioner{
				Type:          stepProvisionerSCEP,
				Name:          []byte("scep"),
				KeyValuePairs: []string{"lonely"},
			},
			want: `{"type":"SCEP","name":"scep","key_value_pairs":{"lonely":""}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(&tt.in)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON =\n %s\nwant\n %s", got, tt.want)
			}
		})
	}
}
