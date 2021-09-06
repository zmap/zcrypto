package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSVersions(t *testing.T) {
	tests := []struct {
		version uint16
		addr    string
	}{
		// TODO SSL 3
		//{VersionSSL30, "172.17.0.2:443"},
		{VersionTLS10, "tls-v1-0.badssl.com:1010"},
		{VersionTLS11, "tls-v1-1.badssl.com:1011"},
		{VersionTLS12, "tls-v1-2.badssl.com:1012"},
		//{VersionTLS13, "tls-v1-3.badssl.com:1013"},
	}

	for _, test := range tests {
		t.Run(TLSVersion(test.version).String(), func(t *testing.T) {

			config := Config{
				InsecureSkipVerify: true,
				MaxVersion:         test.version,
			}
			conn, err := Dial("tcp", test.addr, &config)

			require.NoError(t, err)
			defer conn.Close()

			if log := conn.handshakeLog; assert.NotNil(t, log) {
				assert.EqualValues(t, test.version, conn.handshakeLog.ServerHello.Version)
			}
		})
	}
}

func TestCipherSuitesBadSSL(t *testing.T) {
	tests := []struct {
		cipherSuite uint16
		addr        string
	}{
		//{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, ""},
		//{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ""},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ""},
		{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ""},
		{TLS_ECDHE_RSA_WITH_RC4_128_SHA, "rc4.badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, ""},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "badssl.com:443"},
		//TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ""},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, ""},
		//{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "ecc384.badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, ""},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "badssl.com:443"},
		//{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ""},
		//{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_AES_128_CBC_SHA, "badssl.com:443"},
		//{TLS_DHE_RSA_WITH_AES_256_CBC_SHA, "badssl.com:443"},
		{TLS_RSA_WITH_AES_128_GCM_SHA256, "badssl.com:443"},
		{TLS_RSA_WITH_AES_256_GCM_SHA384, "badssl.com:443"},
		{TLS_RSA_WITH_RC4_128_SHA, "rc4.badssl.com:443"},
		//{TLS_RSA_WITH_RC4_128_MD5, "rc4-md5.badssl.com:443"},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, "badssl.com:443"},
		//{TLS_RSA_WITH_AES_256_CBC_SHA256, "badssl.com:443"},
		{TLS_RSA_WITH_AES_128_CBC_SHA, "badssl.com:443"},
		{TLS_RSA_WITH_AES_256_CBC_SHA, "badssl.com:443"},
		{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "3des.badssl.com:443"},
		//{TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, "3des.badssl.com:443"},
		{TLS_RSA_WITH_3DES_EDE_CBC_SHA, "3des.badssl.com:443"},
		//{TLS_RSA_EXPORT_WITH_RC4_40_MD5, ""},
		//{TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, ""},
		//{TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, ""},
		//{TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, ""},
		//{TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, ""},
		//{TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA, ""},
		//{TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5, ""},
		//{TLS_DHE_DSS_WITH_AES_128_CBC_SHA, ""},
		//{TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, ""},
		//{TLS_DHE_DSS_WITH_DES_CBC_SHA, ""},
		//{TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, ""},
		//{TLS_DHE_RSA_WITH_DES_CBC_SHA, ""},
		//{TLS_DHE_DSS_WITH_AES_256_CBC_SHA, ""},
		//{TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, ""},
		//{TLS_DHE_DSS_WITH_RC4_128_SHA, ""},
		//{TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, ""},
		//{TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, ""},
		//{TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, ""},
	} //

	for _, test := range tests {
		cs := CipherSuiteID(test.cipherSuite)
		t.Run(cs.String(), func(t *testing.T) {

			config := Config{
				InsecureSkipVerify: true,
				CipherSuites:       []uint16{test.cipherSuite},
			}
			conn, err := Dial("tcp", test.addr, &config)

			require.NoError(t, err)
			defer conn.Close()

			if log := conn.handshakeLog; assert.NotNil(t, log) {
				assert.EqualValues(t, cs, conn.handshakeLog.ServerHello.CipherSuite)
			}
		})
	}
}
