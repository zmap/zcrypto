package ja3

import (
	"crypto/md5"
	"strconv"
	"strings"

	"github.com/zmap/zcrypto"
	"github.com/zmap/zcrypto/tls"
)

// ClientFingerprint is a byte-array calculated following the method for calculating JA3
// ClientHello fingerprints.
type ClientFingerprint zcrypto.Fingerprint

// ServerFingerprint is a byte-array calculated following the method for a JA3
// ServerHello fingerprint.
type ServerFingerprint zcrypto.Fingerprint

// JA3 is a method of TLS fingerprinting that was inspired by the research and
// works of Lee Brotherston and his TLS Fingerprinting tool: FingerprinTLS.
//
// JA3 gathers the decimal values of the bytes for the following fields in the
// Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions,
// Elliptic Curves, and Elliptic Curve Formats. It then concatenates those
// values together in order, using a "," to delimit each field and a "-" to
// delimit each value in each field. The field order is as follows:
//
// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//
// Example:
//
// 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
//
// If there are no SSL Extensions in the Client Hello, the fields are left
// empty.
//
// Example:
//
// 769,4-5-10-9-100-98-3-6-19-18-99,,,
// These strings are then MD5 hashed to produce an easily consumable and
// shareable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.
//
// 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
// 769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
// We also needed to introduce some code to account for Google’s GREASE (Generate Random Extensions And Sustain Extensibility) as described here. Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem. JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.

func GenerateClientFingerprint(hs *tls.ServerHandshake) ClientFingerprint {
	ch := hs.ClientHello
	decimalRepresentations := make([]string, 0, 5)

	// SSLVersion
	decimalVersion := strconv.Itoa(int(ch.Version))
	decimalRepresentations = append(decimalRepresentations, decimalVersion)

	// Cipher
	// TODO: Handle Grease
	decimalCiphers := make([]string, len(ch.CipherSuites))
	for idx, cipher := range ch.CipherSuites {
		decimalCiphers[idx] = strconv.Itoa(int(cipher))
	}
	joinedCiphers := strings.Join(decimalCiphers, "-")
	decimalRepresentations = append(decimalRepresentations, joinedCiphers)

	// SSLExtension
	// TODO
	decimalRepresentations = append(decimalRepresentations, "")

	// EllipticCurve
	// TODO
	decimalRepresentations = append(decimalRepresentations, "")

	// EllipticCurvePointFormat
	// TODO
	decimalRepresentations = append(decimalRepresentations, "")

	ja3Input := strings.Join(decimalRepresentations, ",")
	ja3 := md5.Sum([]byte(ja3Input))
	return ja3[:]
}

func GenerateServerFingerprint() ServerFingerprint {
	return nil
}
