package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// selfSignedTestCertificate returns a self-signed certificate for priv that
// is valid for both server and client authentication.
func selfSignedTestCertificate(t *testing.T, priv crypto.Signer) Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestTLS12ServerKeyExchangeLogHash checks that the TLS 1.2 handshake log
// names the hash algorithm the server actually used to sign the
// ServerKeyExchange.
func TestTLS12ServerKeyExchangeLogHash(t *testing.T) {
	for _, tc := range []struct {
		name   string
		curve  elliptic.Curve
		scheme SignatureScheme
		hash   string
	}{
		{"P256-SHA256", elliptic.P256(), ECDSAWithP256AndSHA256, "sha256"},
		{"P384-SHA384", elliptic.P384(), ECDSAWithP384AndSHA384, "sha384"},
		{"P521-SHA512", elliptic.P521(), ECDSAWithP521AndSHA512, "sha512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := selfSignedTestCertificate(t, priv)
			cert.SupportedSignatureAlgorithms = []SignatureScheme{tc.scheme}

			serverConfig := &Config{
				Certificates: []Certificate{cert},
				MaxVersion:   VersionTLS12,
			}
			clientConfig := &Config{
				InsecureSkipVerify: true,
				MaxVersion:         VersionTLS12,
				CipherSuites:       []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			}

			c, s := localPipe(t)
			serverErr := make(chan error, 1)
			go func() {
				srv := Server(s, serverConfig)
				serverErr <- srv.Handshake()
				srv.Close()
			}()
			cli := Client(c, clientConfig)
			if err := cli.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			defer cli.Close()
			if err := <-serverErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}

			sh := cli.handshakeLog.ServerKeyExchange.Signature.SigHashExtension
			if sh == nil {
				t.Fatal("no signature_and_hash_type logged")
			}
			if got := nameForHash(sh.Hash); got != tc.hash {
				t.Errorf("logged hash algorithm = %q, want %q", got, tc.hash)
			}
		})
	}
}
