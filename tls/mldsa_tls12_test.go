package tls

import (
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ka.verifyError == nil {
		t.Fatal("expected bogus ML-DSA signature to fail verification")
	}
}
