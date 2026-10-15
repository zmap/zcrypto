package tls

import (
	"crypto/mldsa"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/curve25519"
)

// TestTLS12MLDSAServerKeyExchange feeds the client a TLS 1.2 ECDHE
// ServerKeyExchange signed with ML-DSA-44, as a (malicious or merely
// permissive) server could send. The client advertises ML-DSA in its
// signature_algorithms, so it must handle the server picking it without
// panicking. A bogus signature should produce a verify error, not a crash.
func TestTLS12MLDSAServerKeyExchange(t *testing.T) {
	serverPub, err := curve25519.X25519(make([]byte, 32), curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	// ECParameters: named_curve(3), X25519, len, point
	key := []byte{3, byte(X25519 >> 8), byte(X25519), byte(len(serverPub))}
	key = append(key, serverPub...)
	// SignatureScheme ML-DSA-44, then a 4-byte junk signature.
	sigScheme := MLDSA44Sig
	key = append(key, byte(sigScheme>>8), byte(sigScheme), 0, 4, 1, 2, 3, 4)

	clientHello := &clientHelloMsg{
		random:                       make([]byte, 32),
		supportedSignatureAlgorithms: supportedSignatureAlgorithms,
	}
	serverHello := &serverHelloMsg{random: make([]byte, 32)}

	ka := &ecdheKeyAgreement{
		auth:    &signedKeyAgreement{version: VersionTLS12},
		version: VersionTLS12,
		isRSA:   false, // ECDHE_ECDSA suite
	}
	err = ka.processServerKeyExchange(&Config{}, clientHello, serverHello, &x509.Certificate{}, &serverKeyExchangeMsg{key: key})
	if err == nil || ka.verifyError == nil {
		t.Fatal("expected bogus ML-DSA signature to fail verification")
	}
}

func mldsaTestCertificate(t *testing.T, params mldsa.Parameters) Certificate {
	t.Helper()
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	return selfSignedTestCertificate(t, priv)
}

// TestTLS12MLDSAHandshake runs TLS 1.2 handshakes authenticated with ML-DSA
// server and client certificates. ML-DSA is only specified for TLS 1.3, but
// nothing in the TLS 1.2 messages prevents it, and a measurement tool should
// handle whatever servers send.
func TestTLS12MLDSAHandshake(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
	}{
		{"mldsa44", mldsa.MLDSA44()},
		{"mldsa65", mldsa.MLDSA65()},
		{"mldsa87", mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := &Config{
				Certificates: []Certificate{mldsaTestCertificate(t, tc.params)},
				MaxVersion:   VersionTLS12,
				ClientAuth:   RequireAnyClientCert,
			}
			clientConfig := &Config{
				Certificates:       []Certificate{mldsaTestCertificate(t, tc.params)},
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

			if v := cli.ConnectionState().Version; v != VersionTLS12 {
				t.Fatalf("negotiated version %x, want TLS 1.2", v)
			}
			sig := cli.handshakeLog.ServerKeyExchange.Signature
			if !sig.Valid {
				t.Error("ServerKeyExchange signature logged as invalid")
			}
			if sig.Type != tc.name {
				t.Errorf("logged signature type = %q, want %q", sig.Type, tc.name)
			}
		})
	}
}
