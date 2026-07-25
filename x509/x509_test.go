// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	"github.com/zmap/zcrypto/dsa"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E.Cmp(rsaPrivateKey.PublicKey.E) != 0 ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	pub, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse RSA public key: %s", err)
		return
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
		return
	}

	pubBytes2, err := MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Errorf("Failed to marshal RSA public key for the second time: %s", err)
		return
	}
	if !bytes.Equal(pubBytes2, block.Bytes) {
		t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
	}
}

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

var pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA PRIVATE KEY-----
`

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

func fromBase10(base10 string) *big.Int {
	i := new(big.Int)
	i.SetString(base10, 10)
	return i
}

func bigFromHexString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 16)
	return ret
}

var rsaPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077"),
		E: big.NewInt(65537),
	},
	D: bigFromString("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861"),
	Primes: []*big.Int{
		bigFromString("98920366548084643601728869055592650835572950932266967461790948584315647051443"),
		bigFromString("94560208308847015747498523884063394671606671904944666360068158221458669711639"),
	},
}

func TestMarshalRSAPrivateKey(t *testing.T) {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
			E: big.NewInt(3),
		},
		D: fromBase10("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
		Primes: []*big.Int{
			fromBase10("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
			fromBase10("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
			fromBase10("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
		},
	}

	derBytes := MarshalPKCS1PrivateKey(priv)

	priv2, err := ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		t.Errorf("error parsing serialized key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(priv2.PublicKey.N) != 0 ||
		priv.PublicKey.E.Cmp(priv2.PublicKey.E) != 0 || // ZCrypto - needed to swap to using bigint.Cmp here
		priv.D.Cmp(priv2.D) != 0 ||
		len(priv2.Primes) != 3 ||
		priv.Primes[0].Cmp(priv2.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(priv2.Primes[1]) != 0 ||
		priv.Primes[2].Cmp(priv2.Primes[2]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, priv2)
	}
}

type matchHostnamesTest struct {
	pattern, host string
	ok            bool
}

var matchHostnamesTests = []matchHostnamesTest{
	{"a.b.c", "a.b.c", true},
	{"a.b.c", "b.b.c", false},
	{"", "b.b.c", false},
	{"a.b.c", "", false},
	{"example.com", "example.com", true},
	{"example.com", "www.example.com", false},
	{"*.example.com", "www.example.com", true},
	{"*.example.com", "xyz.www.example.com", false},
	{"*.*.example.com", "xyz.www.example.com", true},
	{"*.www.*.com", "xyz.www.example.com", true},
}

func TestCertificateParse(t *testing.T) {
	s, _ := hex.DecodeString(certBytes)
	certs, err := ParseCertificates(s)
	if err != nil {
		t.Error(err)
	}
	if len(certs) != 2 {
		t.Errorf("Wrong number of certs: got %d want 2", len(certs))
		return
	}

	err = certs[0].CheckSignatureFrom(certs[1])
	if err != nil {
		t.Error(err)
	}

	const expectedExtensions = 4
	if n := len(certs[0].Extensions); n != expectedExtensions {
		t.Errorf("want %d extensions, got %d", expectedExtensions, n)
	}

	if extMap := certs[0].ExtensionsMap; extMap == nil {
		t.Fatal("expected non-nil ExtensionsMap, got nil")
	} else if len(extMap) != expectedExtensions {
		t.Errorf("wanted %d extensions in ExtensionsMap, got %d",
			expectedExtensions, len(extMap))
	}

	expectedOIDs := []string{
		"2.5.29.31",
		"1.3.6.1.5.5.7.1.1",
		"2.5.29.19",
		"2.5.29.37",
	}
	for _, expectedOID := range expectedOIDs {
		if ext, present := certs[0].ExtensionsMap[expectedOID]; !present {
			t.Errorf("expected oid %q missing in ExtensionsMap", expectedOID)
		} else if ext.Id.String() != expectedOID {
			t.Errorf("expected oid %q in ExtensionsMap to key "+
				"pkix.Extension with same oid, got %q",
				expectedOID, ext.Id.String())
		}
	}
}

var certBytes = "308203223082028ba00302010202106edf0d9499fd4533dd1297fc42a93be1300d06092a864886" +
	"f70d0101050500304c310b3009060355040613025a4131253023060355040a131c546861777465" +
	"20436f6e73756c74696e67202850747929204c74642e311630140603550403130d546861777465" +
	"20534743204341301e170d3039303332353136343932395a170d3130303332353136343932395a" +
	"3069310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630" +
	"140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c6520" +
	"496e63311830160603550403130f6d61696c2e676f6f676c652e636f6d30819f300d06092a8648" +
	"86f70d010101050003818d0030818902818100c5d6f892fccaf5614b064149e80a2c9581a218ef" +
	"41ec35bd7a58125ae76f9ea54ddc893abbeb029f6b73616bf0ffd868791fba7af9c4aebf3706ba" +
	"3eeaeed27435b4ddcfb157c05f351d66aa87fee0de072d66d773affbd36ab78bef090e0cc861a9" +
	"03ac90dd98b51c9c41566c017f0beec3bff391051ffba0f5cc6850ad2a590203010001a381e730" +
	"81e430280603551d250421301f06082b0601050507030106082b06010505070302060960864801" +
	"86f842040130360603551d1f042f302d302ba029a0278625687474703a2f2f63726c2e74686177" +
	"74652e636f6d2f54686177746553474343412e63726c307206082b060105050701010466306430" +
	"2206082b060105050730018616687474703a2f2f6f6373702e7468617774652e636f6d303e0608" +
	"2b060105050730028632687474703a2f2f7777772e7468617774652e636f6d2f7265706f736974" +
	"6f72792f5468617774655f5347435f43412e637274300c0603551d130101ff04023000300d0609" +
	"2a864886f70d01010505000381810062f1f3050ebc105e497c7aedf87e24d2f4a986bb3b837bd1" +
	"9b91ebcad98b065992f6bd2b49b7d6d3cb2e427a99d606c7b1d46352527fac39e6a8b6726de5bf" +
	"70212a52cba07634a5e332011bd1868e78eb5e3c93cf03072276786f207494feaa0ed9d53b2110" +
	"a76571f90209cdae884385c882587030ee15f33d761e2e45a6bc308203233082028ca003020102" +
	"020430000002300d06092a864886f70d0101050500305f310b3009060355040613025553311730" +
	"15060355040a130e566572695369676e2c20496e632e31373035060355040b132e436c61737320" +
	"33205075626c6963205072696d6172792043657274696669636174696f6e20417574686f726974" +
	"79301e170d3034303531333030303030305a170d3134303531323233353935395a304c310b3009" +
	"060355040613025a4131253023060355040a131c54686177746520436f6e73756c74696e672028" +
	"50747929204c74642e311630140603550403130d5468617774652053474320434130819f300d06" +
	"092a864886f70d010101050003818d0030818902818100d4d367d08d157faecd31fe7d1d91a13f" +
	"0b713cacccc864fb63fc324b0794bd6f80ba2fe10493c033fc093323e90b742b71c403c6d2cde2" +
	"2ff50963cdff48a500bfe0e7f388b72d32de9836e60aad007bc4644a3b847503f270927d0e62f5" +
	"21ab693684317590f8bfc76c881b06957cc9e5a8de75a12c7a68dfd5ca1c875860190203010001" +
	"a381fe3081fb30120603551d130101ff040830060101ff020100300b0603551d0f040403020106" +
	"301106096086480186f842010104040302010630280603551d110421301fa41d301b3119301706" +
	"035504031310507269766174654c6162656c332d313530310603551d1f042a30283026a024a022" +
	"8620687474703a2f2f63726c2e766572697369676e2e636f6d2f706361332e63726c303206082b" +
	"0601050507010104263024302206082b060105050730018616687474703a2f2f6f6373702e7468" +
	"617774652e636f6d30340603551d25042d302b06082b0601050507030106082b06010505070302" +
	"06096086480186f8420401060a6086480186f845010801300d06092a864886f70d010105050003" +
	"81810055ac63eadea1ddd2905f9f0bce76be13518f93d9052bc81b774bad6950a1eededcfddb07" +
	"e9e83994dcab72792f06bfab8170c4a8edea5334edef1e53d906c7562bd15cf4d18a8eb42bb137" +
	"9048084225c53e8acb7feb6f04d16dc574a2f7a27c7b603c77cd0ece48027f012fb69b37e02a2a" +
	"36dcd585d6ace53f546f961e05af"

func TestCreateSelfSignedCertificate(t *testing.T) {
	random := rand.Reader

	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %s", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	mldsa44Pub, mldsa44Priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA44 key: %s", err)
	}

	mldsa65Pub, mldsa65Priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA65 key: %s", err)
	}

	mldsa87Pub, mldsa87Priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA87 key: %s", err)
	}

	byt := make([]byte, 0)
	null := asn1.BitString{Bytes: byt, BitLength: 0}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	x25519Pub := X25519PublicKey(pubkey[:])

	tests := []struct {
		name       string
		pub, priv  interface{}
		checkSig   bool
		sigAlgo    SignatureAlgorithm
		selfSigned bool
	}{
		{"RSA/RSA", &rsaPriv.PublicKey, rsaPriv, true, SHA1WithRSA, true},
		{"RSA/ECDSA", &rsaPriv.PublicKey, ecdsaPriv, false, ECDSAWithSHA384, false},
		{"ECDSA/RSA", &AugmentedECDSA{Pub: &ecdsaPriv.PublicKey, Raw: null}, rsaPriv, false, SHA256WithRSA, false},
		{"ECDSA/ECDSA", &AugmentedECDSA{Pub: &ecdsaPriv.PublicKey, Raw: null}, ecdsaPriv, true, ECDSAWithSHA1, true},
		{"MLDSA44/MLDSA44", mldsa44Pub, mldsa44Priv, true, MLDSA44Sig, true},
		{"MLDSA65/MLDSA65", mldsa65Pub, mldsa65Priv, true, MLDSA65Sig, true},
		{"MLDSA87/MLDSA87", mldsa87Pub, mldsa87Priv, true, MLDSA87Sig, true},
		{"MLDSA44/ECDSA", mldsa44Pub, ecdsaPriv, false, ECDSAWithSHA1, false},
		{"RSA/MLDSA65", &rsaPriv.PublicKey, mldsa65Priv, false, MLDSA65Sig, false},
		{"Ed25519/Ed25519", ed25519Pub, ed25519Priv, true, Ed25519Sig, true},
		{"X25519/Ed25519", x25519Pub, ed25519Priv, false, Ed25519Sig, false},
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		template := Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA:                  true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

			PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 23, 140, 1, 1}},
			PermittedDNSNames: []GeneralSubtreeString{{Data: ".example.com"}, {Data: "example.com"}},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       oidExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := CreateCertificate(random, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.PolicyIdentifiers) != 2 || !cert.PolicyIdentifiers[0].Equal(template.PolicyIdentifiers[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.PolicyIdentifiers)
		}

		if len(cert.PermittedDNSNames) != 2 || cert.PermittedDNSNames[0].Data != ".example.com" || cert.PermittedDNSNames[1].Data != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSNames)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
			t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if cert.SelfSigned != test.selfSigned {
			t.Errorf("%s: SelfSigned was not set properly. Got %v, want %v", test.name, cert.SelfSigned, test.selfSigned)
		}

		if !cert.SelfSigned {
			if cert.ValidationLevel != EV {
				t.Errorf("%s: ValidationLevel was not set properly. Got %s, want %s", test.name, cert.ValidationLevel.String(), EV.String())
			}
		}

		if !reflect.DeepEqual(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !reflect.DeepEqual(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if !reflect.DeepEqual(cert.IPAddresses, template.IPAddresses) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if bytes.Index(derBytes, extraExtensionData) == -1 {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = cert.CheckSignatureFrom(cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

// Self-signed certificate using ECDSA with SHA1 & secp256r1
var ecdsaSHA1CertPem = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbUCCQDF6SfN0nsnrjAJBgcqhkjOPQQBMIGPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMG
A1UECgwMR29vZ2xlLCBJbmMuMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIwMjAyMDUw
WhcNMjIwNTE4MjAyMDUwWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwg
SW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAhBgkqhkiG9w0BCQEWFGdv
bGFuZy1kZXZAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/Wgn
WQDo5+bz71T0327ERgd5SDDXFbXLpzIZDXTkjpe8QTEbsF+ezsQfrekrpDPC4Cd3
P9LY0tG+aI8IyVKdUjAJBgcqhkjOPQQBA0gAMEUCIGlsqMcRqWVIWTD6wXwe6Jk2
DKxL46r/FLgJYnzBEH99AiEA3fBouObsvV1R3oVkb4BQYnD4/4LeId6lAT43YvyV
a/A=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp256r1
var ecdsaSHA256p256CertPem = `
-----BEGIN CERTIFICATE-----
MIICDzCCAbYCCQDlsuMWvgQzhTAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAh
BgkqhkiG9w0BCQEWFGdvbGFuZy1kZXZAZ21haWwuY29tMB4XDTEyMDUyMTAwMTkx
NloXDTIyMDUxOTAwMTkxNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUs
IEluYy4xFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRn
b2xhbmctZGV2QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPMt
2ErhxAty5EJRu9yM+MTy+hUXm3pdW1ensAv382KoGExSXAFWP7pjJnNtHO+XSwVm
YNtqjcAGFKpweoN//kQwCgYIKoZIzj0EAwIDRwAwRAIgIYSaUA/IB81gjbIw/hUV
70twxJr5EcgOo0hLp3Jm+EYCIFDO3NNcgmURbJ1kfoS3N/0O+irUtoPw38YoNkqJ
h5wi
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp384r1
var ecdsaSHA256p384CertPem = `
-----BEGIN CERTIFICATE-----
MIICSjCCAdECCQDje/no7mXkVzAKBggqhkjOPQQDAjCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMDYxMDM0
WhcNMjIwNTE5MDYxMDM0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARRuzRNIKRK
jIktEmXanNmrTR/q/FaHXLhWRZ6nHWe26Fw7Rsrbk+VjGy4vfWtNn7xSFKrOu5ze
qxKnmE0h5E480MNgrUiRkaGO2GMJJVmxx20aqkXOk59U8yGA4CghE6MwCgYIKoZI
zj0EAwIDZwAwZAIwBZEN8gvmRmfeP/9C1PRLzODIY4JqWub2PLRT4mv9GU+yw3Gr
PU9A3CHMdEcdw/MEAjBBO1lId8KOCh9UZunsSMfqXiVurpzmhWd6VYZ/32G+M+Mh
3yILeYQzllt/g0rKVRk=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA384 & secp521r1
var ecdsaSHA384p521CertPem = `
-----BEGIN CERTIFICATE-----
MIICljCCAfcCCQDhp1AFD/ahKjAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMTUwNDI5
WhcNMjIwNTE5MTUwNDI5WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACqx9Rv
IssRs1LWYcNN+WffwlHw4Tv3y8/LIAA9MF1ZScIonU9nRMxt4a2uGJVCPDw6JHpz
PaYc0E9puLoE9AfKpwFr59Jkot7dBg55SKPEFkddoip/rvmN7NPAWjMBirOwjOkm
8FPthvPhGPqsu9AvgVuHu3PosWiHGNrhh379pva8MzAKBggqhkjOPQQDAwOBjAAw
gYgCQgEHNmswkUdPpHqrVxp9PvLVl+xxPuHBkT+75z9JizyxtqykHQo9Uh6SWCYH
BF9KLolo01wMt8DjoYP5Fb3j5MH7xwJCAbWZzTOp4l4DPkIvAh4LeC4VWbwPPyqh
kBg71w/iEcSY3wUKgHGcJJrObZw7wys91I5kENljqw/Samdr3ka+jBJa
-----END CERTIFICATE-----
`

var ecdsaTests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{ECDSAWithSHA1, ecdsaSHA1CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p256CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p384CertPem},
	{ECDSAWithSHA384, ecdsaSHA384p521CertPem},
}

func TestECDSA(t *testing.T) {
	for i, test := range ecdsaTests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*AugmentedECDSA); !ok {
			t.Errorf("%d: wanted an AugmentedECDSA public key but found: %#v", i, parsedKey)
		}
		//      if parsedKey, ok := cert.PublicKey.Pub(*ecdsa.PublicKey); !ok {
		//          t.Errorf("%d: wanted an ECDSA public key but found: %#v", i, parsedKey)
		//      }
		//      if parsedKey, ok := cert.PublicKey.Raw(*asn.BitString); !ok {
		//          t.Errorf("%d: wanted an ECDSA public key but found: %#v", i, parsedKey)
		//      }
		if pka := cert.PublicKeyAlgorithm; pka != ECDSA {
			t.Errorf("%d: public key algorithm is %v, want ECDSA", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

// Self Signed MLDSA 44 Certificate
var mldsa44CertPem = `
-----BEGIN CERTIFICATE-----
MIIQfDCCBvKgAwIBAgIBATALBglghkgBZQMEAxEwRzEZMBcGA1UEAxMQdGVzdC5l
eGFtcGxlLmNvbTEdMBsGA1UEChMURXhhbXBsZSBPcmdhbml6YXRpb24xCzAJBgNV
BAYTAlVTMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowRzEZMBcGA1UE
AxMQdGVzdC5leGFtcGxlLmNvbTEdMBsGA1UEChMURXhhbXBsZSBPcmdhbml6YXRp
b24xCzAJBgNVBAYTAlVTMIIFMjALBglghkgBZQMEAxEDggUhACkEVII0Q0cBOo26
llnb+mi7gIpOeIEb9zqFNwqH9PKkzHY3jL5Dbtf0ICxcdWBAI2GZjmLxVolM4fyA
jceX7pEmSxWF3/UDLnnXZIkJhEXAsEZLC4G/tqMUSnTJvrJ40EmDDZlw2arFp2k/
bP/oNx0TumnW5LAj2b56FCr16mBcRkTRz3KYRsdreieP2T/B3mPMKuTdjGKOV0vK
JB/+IuxdkZoT2/o1+oubaW2CS7pDkO0V2wmeX/gjBaITFDi+7fxtFBaEjLB9XDuN
f57dH5q/4nQn+g2y2Ui49HMpufS/pLLbtptuoaJDQwifrQLZrr7SMpik1CKrO+Bd
Eq/o/KrkscL3XHN8SUSrYv8q3Ega4Elc3MuPbW534Tv/iwv03dkutAsBKk2UwUh/
HxdlZd4cFAKHYhaGkGa5xKv658ahUkRWyaLHZZWt2maahMI/BBo4rG2w7S4XaFJQ
mVCbCs9sajhCTt6stX0YQAlBGYxbo5i4hijK+Jb/Pie3O9dmnpA4A6Xpkj1AbVKu
zo8JRQYWoyS0O0zSujvudBL74Jzv1/AZVRhxeCfxdjyEIZ3r3iikDuLyscTAHr5k
Hv3kFEYtuisNPbSZn10r+J6u5TJqyhPMCHisLYKJSNVHz/fsvEx3vwrCi94ENJTc
Dnb6QPh8fkcWfFAHkVOhru29SZOT+usQ1YfDWI+N4K9RQYMp8eI35hWRLl4i4+ml
ZucnyVumEZtvpqnu7MPt4Z86bfvaafyq/2Q77rKbSpMQFIpwDHB5TsYRtS7Q9+QR
mwS6coxTymwNZGUyaxL5Syuh7OuMeFahJpc8kAhATM9AfYPqwXolPAjH8WQOhznp
11c9q4c5N2dWbkBNcmyNxnnOFBerBb/xuG2UglNvN34ZCp9DRrJ3yD/t4ig3JeKK
r83Zc7E4vBSzqXk7uBWxH3OLmcy4qZ76P5uJf1R3xvXxw8kP1qBilBp0nALu8+iY
SGjmM8WNwa8/96pk8aRKP1Ews5BIODXX09ouOCNW2YKvwgarSWsXfbZdwQL80b1C
uDJFYW46yTYNCAt6EuncIjWUVpBKhv4BDHws/aPO/vyWdZEbqx4+Ql3Xfe6KRUvV
5rmuIMb20dJ/HB6a4OvfCVmAFIR7CA7Vjf6Qx34NRwjxTmz78E3/UNkfEtobTDwi
S1JvbihQ9dce41HsmbuYgSRUaiR0yClq07+w+inGjiI4YeKy2+Rtg8Fw0XXWhb5S
w1jzwsbixv1OB7zhCbdJjDgY+Md5YfqoQDButyx7ug5JilAdVxlMSjF/6F4WrKln
vpjfVpIzutaQHFmTB1WyDffPGJhJ99gADQ71g645RsGby9vQy6q+rdDzLdUtZudy
Ijov6yRZNSP8OYeAzXPBVBZZ8EVxr5lI22ae+V/JeuXm2wBt2NXur8/SDzfMKR/+
Ndi10ANmjcHnmSTZdOPW4E8LaeOyG2gZ2pkUaqnmieYQ6cgMC1bAfte87E6BEA54
Ff5R4+aOx/oZKJea0yER7m1p28/nj17Zmw4bM8F8++d6RQV49UouInJLeIdbYbOB
DTcfmpVeEsM7dl50V+qqQIWeSNR65IIo3aXG58HSjRG0nmqlYg17cx5ysM+RywOV
DAx8UkANyPNr0B8EduRRpDrRGKT2bN/15nJQJQUcAuZpHHsT3u/JYoG0oZbN7NXj
kcIJiDEPZv0DTmyomDGvpjl63Q6oJHKLVVrwRc+XLc1OQr0LxqajUVNgUXYRVPDf
TZ0dviSjgfIwge8wDgYDVR0PAQH/BAQDAgKEMA8GA1UdEwEB/wQFMAMBAf8wDQYD
VR0OBAYEBAECAwQwXgYIKwYBBQUHAQEEUjBQMCMGCCsGAQUFBzABhhdodHRwOi8v
b2NzcC5leGFtcGxlLmNvbTApBggrBgEFBQcwAoYdaHR0cDovL2NydC5leGFtcGxl
LmNvbS9jYS5jcnQwLQYDVR0RBCYwJIIQdGVzdC5leGFtcGxlLmNvbYEQdGVzdEBl
eGFtcGxlLmNvbTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmV4YW1wbGUu
Y29tL2NhLmNybDALBglghkgBZQMEAxEDggl1ADunNEJWuaRYMKUCYuRmeQQVDCwH
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
-----END CERTIFICATE-----
`

// Self Signed MLDSA 65 Certificate
var mldsa65CertPem = `
-----BEGIN CERTIFICATE-----
MIIWdTCCCXKgAwIBAgIBATALBglghkgBZQMEAxIwRzEZMBcGA1UEAxMQdGVzdC5l
eGFtcGxlLmNvbTEdMBsGA1UEChMURXhhbXBsZSBPcmdhbml6YXRpb24xCzAJBgNV
BAYTAlVTMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowRzEZMBcGA1UE
AxMQdGVzdC5leGFtcGxlLmNvbTEdMBsGA1UEChMURXhhbXBsZSBPcmdhbml6YXRp
b24xCzAJBgNVBAYTAlVTMIIHsjALBglghkgBZQMEAxIDggehACowxX7nIi2XpYb+
TKVfK2fGkWXSt61PvNEChN43jDIOmXczHEiOc/Ac5NCJtfZuUlrgHLkJCZkdTRwJ
/S2nPBYvL98LHqDvayIz32wbI4o8s3c3omLRIezO6eSw8ob+KHVXVXqUNb+uReur
UTjlncuLbmytKA8cLi499vxpk64KmgeZvskNUV3xEnw32EKACHpS0S9AQuNOM7Vl
oURivR/fsG62klWqbhQvocBhW0QSYgpTOSLmTF6AsAFAyOZcOza6BZfMp/9dVPRs
iMSOR5yFahgem+zPs/2+qIoCC8lfO62NLPEHUbjvwT/de13fufhbZug3xv4xqsxP
+9IcJeFZKZzHjvkXwSIp3RNssBnqiL8GWVzp7nCAI5MEFTKVYk8mKwgbXPVBE6ER
x+bGhHs6pLwPjvWV7jWwi4K+hvTdxdbsE840ZhVbsLWx+kTGLMt4EejdnwhPYYA/
d7sfKG3wqLqncA+NuEyycv22OweUPHuiumfnkmgznQzNcatszcR3T8KGEOj7/9b9
tuZ5VVthpd3dE+wxSsYsZmLJ8+DEw2FfuA0UFTgDwv1uZtcUBPHvKpspXRZzF0hx
tyF9WEuViWbjH/Pi56K2aY/djrve0pCNX/Oki0Ju3im/6wTV1eI1MvlGzd+SX5uk
KvUUfEcND5G/mX9A3qUWBH7XzbFcFjarn35rAj5qVBryuwdQ6O1Vt8kYwbJkgk2E
5eaZ3ZR06zAG83psoHHhGqpWTf1XjMMWLzMoC2uq0qDWv8hkI82JtEOPvNFeH+qR
rEg6T9GayQZkHQZ4unbcfb0GQwBdUKivZGrFxo8VsCzQRoo6pj6UU9UazQuvhkM7
zlt41kYGg5oW8m/2k07hXnighm4WATV//Ae69Ma9QLvZ9PAJpOa76+RBF0g1j+Jy
+/pMU8rON0MgAx5poVzO5VGMGF2FsvdQBr0em4OCRuwrM1EoLEjCYY/2uOQ6rzLb
GDz9DM+bnrKlUBqjwe/wU9fuHz/BV0JTIlUsPY07dG+EZwguam03hBMIWQ+gfCVF
G3X2DeOLHVKtMXemlqo1TPTpRaGlm0sFaVom+GAxNLQx+T0eyaVI6eB93EwYNsEh
3TmX2eQ6zbewclzap/ufAZh80h8FLWLXSh1vqmKE0E9JlQ964yBq9dri/GSgcMYR
t3StOR3buwuizkqqCCMapwljhGc5ESQh7KL6e/obfX+OR82vcZ15QVia25Bk2ABr
cLSwidz2jOk1wwxeFApq/uADXI1FoSkgkbE8jnLphVUqHtymjRzCUJpGU5sxt8wd
X63vvrhpQxBB7q8+MvFdARhz69klvqKjLDOv4P69kgfe8/vNkBa/DeFUWdTg0Nwx
7Pj3zVcLPFuh/DPziLJugOVHysvjp+Osevlz0TcIe9lSK3QI5EoHYkwJwYQmUk0I
cLrXqHkVqOkmvrz6znU92OV+lgl5KFsJCTEJ5eX+p9dSqwtoMMeNS8WycvHOnWy5
PClA2vlAkUqvJO7uGGZObtSFvCsBUvScIJdTjbREh5lGYE26pRYKiaqQWifUueC7
0/AbsYkC4/tWGqnMWalJxdvwnqmhafW06Oel+j5vOAzpG1ITW5n10vy0m6JqbjIc
g74I1srqKXiSqAlpMHxtCQaC+8dLlZvUxcgnlte+6jJdu9E78+DS/jSqn5Re45u5
c5gsM1O6h+4gDITFBzPumEiTk93pCXtAOLvAR1wGhfu2Q7OJDUF1hc+V2P1DhR0d
cJg1DrqCJXIpra4yLnJj0anKs3ZmlGj2K6Ebzmf9DMha7nFwoaQNFomqSiz97tmz
TXBVbZ4qwrwEKDzeNaR8vxMe2EK79Xtie996JEaaNp9/QkzbJ5GPLBu5wNObqcxj
4DESf7fIH5WQttf7kp0mahtW+A6gy+1NwuwpZqNZjpnlLcbNMtEohz0HVxBCp3Gk
h1zz+pSijoAnuqQ2eGPxEDiI4Kv6MA/h1/AryCEn6hmmDMsaa/BTzOXGswzbsA1k
FX9kl146b6kjTtASKgmdFmmkk/CnaTx2fpMLeEU1SGTI6wGuTMAqAaYLcSoTwQZe
a/U+gXW2wrlLptIOuWCusB0j+oXz6XHJqWa+kv2bEjLriBetg+0JefimPYiyw3R/
QiYNO0NVAe/ImPm/VhxmBNHwSaJwUh01iNQjveo4AYfz/jXV3swR6nprv+0itVk1
vTv5UtJsTfztjtsLlO/s86F2qOdfCeWRq2YvpccN099DZstoQm/CLOczgwHiNw0T
eUr3KJw9obqA/BNMyv+L0TJDwNQvHODWEC/e7tTY3zpQsmN9Ja9jR24RqK9Bqrah
PdnHXfx3Jj1lSEeQsOcpSgUFZ2G+NXKttlnEYVJ+JI48UGo/1oygE1kMlnB6BoNQ
KMXgnkUUrZp6NmQHcF/pwIlR8ro5P3aqJXeBLf+tOLBw1gUQ+6lndQG1EdWEn0Fl
RAUpSYkxCsHdBnzRNuDxU5VBaaZbMnaQnmjf6KcMBAJoMnnZGs8rCcDVsfI/AACE
oRQ5TSXL1XZu1Kfc7AMJVUaGltOA4Rg5RRRCdwwT0POi4ngNPKCNvFOCucz3+SlK
QBLvj1ZNP+MJEGA/voPT0jgtUNqko4HyMIHvMA4GA1UdDwEB/wQEAwIChDAPBgNV
HRMBAf8EBTADAQH/MA0GA1UdDgQGBAQBAgMEMF4GCCsGAQUFBwEBBFIwUDAjBggr
BgEFBQcwAYYXaHR0cDovL29jc3AuZXhhbXBsZS5jb20wKQYIKwYBBQUHMAKGHWh0
dHA6Ly9jcnQuZXhhbXBsZS5jb20vY2EuY3J0MC0GA1UdEQQmMCSCEHRlc3QuZXhh
bXBsZS5jb22BEHRlc3RAZXhhbXBsZS5jb20wLgYDVR0fBCcwJTAjoCGgH4YdaHR0
cDovL2NybC5leGFtcGxlLmNvbS9jYS5jcmwwCwYJYIZIAWUDBAMSA4IM7gBMYpqE
HGCazxGFw9ukgxthTpySoH1njy20OCfIHczK/pa46X2bWgnfe5AdtBCnPWTXMhX3
u6LxGrcJYTFGprvMDpzSrEwgggyQaqiCrELr9rGmZYsNF6yP6ANXigPAZ1WugdYB
r5dJboR5c4lFl1znFcMjUIkBOuEb9ZQYUBYJ5zvc10EeOWYSQ5+FCKZt+bmYgsR5
TwvN/47muulMTkpMjyS8yTPXhP0IewsKJwtm45xybsEK/jU8jfyBztU+7zpjeTto
ldKo2DQPKytZF6oUsvM31956FEC3CEv9mJTviWPOcbM5ZggcefIpt5+w+KReHPFS
x4cJEyK/1c2lhVdsl3IcqjSf56GH6O7PJGHzKwPRtBMmhW+uHe6b19QoyyxBydLu
Ji3KJ+vLbwCJQ5PDTD1mn8Yk5zX2isEDh+4kYPgYuYW9esE2gFSKY7fuw6zrKWpI
3EruPVrDINTbDhVkNngwV9KctURhj+O7mhSqBx3HILoyLhGxq7SDgKpmy7Ng3lHD
074EqKDZ7oKcER2lCyfyisLpwcPNVw+efxu7E8mjlu+5TXsEs0dCotDec0nq6BV9
R0PWcXabKLf1TUlj52wqPZPGTjFtH7Grkgkkh1hgohf0NskSpkJd3aivqShoPAs3
NP6L4h4u7EtxIuDPFhZnIwGLS2sk+jok02oszq/9Wpzjfr8T//WWYzmmtZvaaQAZ
1B88Xqt1xhfYG3OgQrg6NiLzLC2D9dF0Jk33eu+V4VBGWQnbgvgGWl6cx7lPxQFE
9EnD6XUw5DPGYtAm6fn5s9xSYBLfJ2QtCVoVtZw2caclaXGqZCAbhFosArDaV9Z+
A4NWZc+lFEd9Clgij5bDPJIa8TPhEvoxkt/xjWHY3iaS0qnKcapPpIysTDXQm0qC
9HfMkzIfN+7+gW19lnVLy5ngfbYdibvf/+PEhyQm2HHbcyIUYjuvqFA65rDXWLGE
5VqoEwg/E5JqG2pz9W1lku0aiI+PV2GzCxT5ykJJdTwFJ0DFe+L6F5Ib0ui3BYBg
AfpZP7c8jc1IMwkUGoVncfXv0KVm8PRHCWIz5gZyZeCnRwWexNKbAqAMaNkLPx9D
VD0gTE6O/Rf8dMPx1Xt27eWRtscWpVChFOFCnTR8XRBfHthzeNWnREaEDkAywxgV
UASbtjvj54euIydpNLWjbYsbWyhW9WKOkK2QHBhiDsNKkbqSTVWgXL/xh9cXmy93
yxGvCpMV0Qs7XrF1jYOHuGkZwBV6gw1HoJ9VhC6Qx9zUIT1ISeNCDzL9KCXFLAbs
nrCYxpQ2qj5XVQcaz9zFWjkt13EAAn353/ANHvQY1EkhHIzHnx9PSsLrj2I5LTcM
jWjYw+VnhK5ZAJ7gfXMf30/nPL+nxmBMctxDDB1OWsEXe3zf3Hi5zLkCExA9sRBx
e7300wcCxwgMIseBZsN4KWeVeeiq7RB5ZBGKvB32cHINUahsaLEJIpRD/vwkDuF9
rLq7C6vwBpP8TTfJRh/98hjURDhelsSkrK6AscnTXsr6xBXD9UzNvYbwci+9n0hc
UfemBoca0N9o0xENCLM3DmdNN5r7UX7F3saMTEUgPgda56lkb8b09n70PtU9p8nB
ntjcN56ohmu8Vf65qG83tetOW3GWd76uBSBnm8Bxs8RDYVuya+abHz/eme9skHA4
oBHIynj/B3Z3ZSMvR5hzc9GqfQ2sQ4gyGJJVMe+3zWDW5df0Etri2qDZ4X9IYxFe
dPtNwEJoJ0eAHueEgaKO/d93VQH0eR08LlYTYc7RkAOmOPGszXZ/RKXUT5BDJFRn
f6vPoby8gtqqrSTS0bjchP60xMOkF3DEXK3LwcuHSrcgxnnx9uNaQRw+/cPmb8g3
yAHRfPMMGsfMtB9DGdnPYUPtJdcLdz1/mUrpAiMaZIFsHCRJ04Pc64IP0ceKU1cM
10s6bE6X5UztY8kttuw7u/QVsc2zjGxnqopmtl3XGjOPbUkvzgd9pXPYN3x4Bsr8
be94LDWXErTLCblGjeo9eLncqpg29dpA4UAXfbzGssopj9UQkXcc9av2PPEWXcjA
gzCzUo3RvshS5Z/bfH2OGOekviT+7LlIVChQRf3rVt7uvOicsFaZ8XpEQgfTJMWC
86MDQT1jqSZVAWpJLv9x3Hjt8iNTnDo2mIyeF65xzhg60GbT34SAg3dZA4Hu5buw
ncLdmyTT706yfyFTPKSKuitLKrNALg5mbqVTJXtm8fkl7tlO953rDBlwoTB9+58a
qstGge0yhuZWaSJ8k58LCxuHAqo8hdOS9tmjBhsog06ykd1TDMLyGZ0EzoDEDAU6
F/nPgMVeIO8JRifGg2h2CBvfEy8lhBUxH/IvZoEzyqaAku+ugUIzooGBMQoP6bh2
6rcAr0ry5t9IUUnbWaPXvSQtuBluJOVdInVVq+DfXJKwQWCs1h9n8tlYbtino/Ft
ynaeFZt/9qbbpcfTXO10kqQPIWyvRolpq63olDoP8EAjLVGwyGxB+lSj6STA68PA
5KheOPmNzni6PcmXiDVdUIlev3KxAPwMYwqXHM/7yEegBRRH9Q2e0atxfC9i/QCu
bg2bPx7Fm0puw4LNesyIy+Gjj1SIKYgBhHbKgu8dCc18qyKwkGmwfNvmVeUvq4yb
4u12PGDmkuxcH8Z5NJuJ3oFBFZM1zGp8JhHvfKilsZazTeSUjN5YPBDiS9fDcRTb
6knk3XPTEvk5S9LP9GKIUAx1VUA5tBhQaeMoj7Q3TVyu7WEMoD+oRHhEa8/292Ej
3TzoHPDgZ44HWlPo48mtyqXVnM9pCg93lyMFFKLrW2a0MPtr7v9fwyatTEzeAi9q
PGVbX2p2HGAl91sli4Xg3Yjy+8C7GcJwANInTaTGou4ClmH+mynHZWMt2PPjH5HW
WGCNSOf9Qui0ih8yu3ItogHROtOQS3MVkyS12/QGtyActyujvw0rfB0iitQngoG4
iXWdD3U1ch9SISbt64JGcQAk4O46TprFxh7ksUbKhyNWhAbk6hC8755VaXad6eKk
fXkBaR1J+f6PKARFL3Ychq1YCwnbEmaTsgWhRUmrXvCqOCOmq756RY5zN3bwwrfm
+WcpE9KLDG1/xOPe9raEsJWv93Db7Xu6wR7pfzLIQ2IQqt1HdC9GEJczQU1DWa3s
MrCOVSXpkanvx3CSpGNlK3DWibKbTbjlgWoPUBH4+wZfcw2XpAreRYgYwRMqi4hl
xBSauIfKAPMfNlrzUiU7x4c3HQU/5pGylRi02nLL1oHwQ5NZLc11wkIVKSOmel0D
UBYiGu7nGPMoGLSNy4MMzCJR+ibDF74mtwjP/f8cREBkycP25HnozxQaK4H6SPNe
8cQ/+MKXiXlDDoufI546NSPg81kfRuoEHaHxN2Yw5igtLHQHgUALSgFU4B9Fi3pN
c9OpZtBf8ninwpRLlp8P8H+/EWu+ys/5biRYb/93WqvZ73T8Ifz9LXzKVR96sPua
Md0lQWNfz+I7QjjfnodFJog0bd/9Qxq5/+KHKYsZfASiCXZFqu0wMH/aU/uRYc5s
sCF0aRK3fSyVZbUm4Q/Enu2R8qBUxJaRXe1McmZe+JbVoGVCsKOkr0t+DyJAIw5Y
MzhmC9I5RmUUs5Tmgy+G6HAqqa4FyMLDuxbveQHmltB4IA7niYVZ5Or872IBg51q
KuLus31oo/wO/t+oBi3tBIvVH/l2NEAq/Cf/AySNtsLM2HVcOOqiCznh3QE1gNSM
HEdtja8n8G6PVXa2J+bffKZyNyqSPGwuSQS2kpnfITyIL3e5X+4vKEHwoRqnQk8x
OU1/kqYWedU3IwoD5Y9uELU43UzfDytqyBdhTa4IHCotSB3ewI24VstpMX2wMPrd
hfLXeKcMyXq7i0D1C3ljOCQ/Q3Vjj9MB0RAWbq1UgWyO/2Bwb3ZUuR+0ZCISiFl/
kiDbJpSXUANixfsHIa9cQOWbjGIyPpLk3S5NmcxO/WHTvLTQooQOzzHKVFyrLatl
B9KNWiO08nvV3E1zXovFCFInXrSgrg+lRdxX7ZcMm4dcSgYZKB1CxfjSXj8YHkCh
3QtoZ6CkWHFSbCl3JnvpUT3NYjOjvrmwk8o4xvFFOO0o0GS1jZXcoHu0WUCTnaN8
LhQwF+s5OKq8xL9exu9k0BpZqS3oJMGg/EU5s/j2m9a6IM4eAOej4bDeasN69FKZ
K4+waN57KwN0jOYEf8rCnYS7Bcrl+7mILjNa4SJs3EsvPwbV5j+40+QdXIc/iQbf
uiLG+F2TwqSNlSdVCJRX7qK5QiKRf3BySf+syHHofeIiihmXddUFco9kvFoc51Eg
3nyQBIUp5x5GybXK2FdmmQ3jnSXNDC6c79sGLTdNxckYX3uM2w4rQUVTlrHX3d7l
+wYIM4GGEEVTaoCyu8DT6+4PJzpManKhzPEAAAAAAAAAAAAECRUaJS4=
-----END CERTIFICATE-----
`

// Self Signed MLDSA87 Certificate
var mldsa87CertPem = `
-----BEGIN CERTIFICATE-----
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
JXyj6rPzddD8cmFvCbz+smVakYICBvwPfD6I4oM0jR0YzcxsEE4TosS7bs/5vppL
MVMjXvt4Z0ib5wkk9RnY/SwRSAiX+TbCsvTRLUKLqaxCFtueZqOB8jCB7zAOBgNV
HQ8BAf8EBAMCAoQwDwYDVR0TAQH/BAUwAwEB/zANBgNVHQ4EBgQEAQIDBDBeBggr
BgEFBQcBAQRSMFAwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1wbGUuY29t
MCkGCCsGAQUFBzAChh1odHRwOi8vY3J0LmV4YW1wbGUuY29tL2NhLmNydDAtBgNV
HREEJjAkghB0ZXN0LmV4YW1wbGUuY29tgRB0ZXN0QGV4YW1wbGUuY29tMC4GA1Ud
HwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuZXhhbXBsZS5jb20vY2EuY3JsMAsGCWCG
SAFlAwQDEwOCEhQALpPOeh5EHRvdR2el16sKMO/T9F+jm40UK02bub0OMZ/345m6
vlcGoXBj7Ge9gVr622V7xezMYI9mAFABQaIDeqQdbo8qpu0fLQt4z0KfwZ7nl99L
rIadEjCK37Jr7EXbjZbbXnQZ9pWaeA35cv121y/j3Klsr+VY/P7RsAM2Ye+EtroD
3OzXVfop4vIVCqSiDIj8IqMJFlLWuUM+eKfGiWmqcluCX41NdOPsnY7kDq5Y+qsM
PrcOgTUW1eokB9XyiH+pea2200lugbdX57SBAbhMeqOLmnx0Crv4GL7L0GgVfupl
5NC6eOe+YQATak4TVMYswVJpDGl9JUn5VjKMWqiIZ0tpC2hkdFFJRnIAT7Xf5MH9
pkb0M53+TXgZfQWPc3tHkTDIw2iNv+hULkt4SFxyHgrBONkOOiyCUCMrRG3OqzNT
ZGrwSRwbZL48XqS3SX1lQUxlWu2FF8OHjVYmPYxMUg9mxk8J6Pqhc3C/10t/iZmq
lD335OdP2+UKhve6Nuoj8bQddKgnqFZFuji/Lo4oZb8URaOWLoZN3Xt7OSR6YaIj
KGufwx5yqsd5uTQ1FjDWMmauvssE2t8/eqk2YO/KyI+w+RZEJUm7DwdqpNcZwrkA
3j60ePmYTNXxnNMtnkdDIDMplw5gGThzwv01pluhJGO/IBD3AfYwWf2z/gpzpDru
vh7OradF/w7qtIDsaMnWPHlsiO9p4gOZ6wNde3le4UkNk5Yr8nooOnA9rE2VtJBz
pIXhz1RpOcf5m4sdBeRW931IvlZYEhAWsNAe53bUID4PidvCQYnchVV018nDMu/e
ClOss8Xcg0xFW3u535u5CeL/HmXjp0vYvvfkdiXWrGEizhLHrX2o/R5h4S/0CE2C
TWq4BPyk8U6jCxSQ8ZJsoRu+t94XooIkPXpjm0IksSyQ+BVOHLWJY5th/k0O6nxG
kAfLvUdLO6NUw9dFJRvO7l7S8IeIRrl8JR9ibPdNmxN7t0GdvSMybJgR1vb1In5U
FGBReAy3nd9rhVOwwkxYf015K8+GrVPvmSpNtAiZsScagMXfitSrevVdudgptDP7
2ykNWLvrmt+juWPZfFTe7PmSoG2G3FEH9DEZ1+I4mkjoWLxGmpXq+QBX0uSYK+/Z
VIgwpuIkglZYSUi+gMvFkEz8zBK9pirQCw+H9Jt/RG9Y0KUc9QVC+tuQlU4L8dwA
4nTe+d5d0lpxybdBi30mimDf6LA63kVPlIoFB+x6jgQtcDHdtMYM4jwKm6CPcIXP
GzhVe8BY/+WPegj6TX+YkHN2XwSBdMu9LTCtLCRLGOQ8O0Bn/5yjd50WfDPow5Cp
phyeg8t9ovK9sUGQ0miWwMuy34FmK8bqlNcCOuLInSNzImxSa/1wUKQME2t72ote
pmLYDajCy2AJY3Qhtad0FhpyX9JXIgcu36QGhQbF1eeLtYNgVtlydoThKGR8j0B5
kjqz3qOa96BXfllvinRJbJytKVbFF0+XPpkXlPDukuS578UEU5W167qHmLJfwYLq
KR+KRW3nh0PIC3CXnanmaFCzG06C0VvHLNYLOxVGjGaPEt+Y5xVpTg4y7DRgUyIr
zi8na0uZaWTbVbEVSbEgjDOGsxYhwXPGVju/qngGG0/7ebrYALB8Cqkpng2k3d7m
AbZz1ba5k4/6/SnBDamiEOrpXsMSiJH3dYiM7A6WXAVwPGEC/quLaX/y4j6Iw3IF
jY0kNmB7+K+vJL1Y/ddxqoWafpSwmBOOq91L5jLYwQW9tk2nFzpqfEGU0+jnxO/C
eeH5IzTz2WPiiFDevVbwoP0YweEw+UjEnXsyE2MyfrQ4oYn4U0U4swyDKu6APN8B
9kG6GOqXB/ZV4Ft6hBkWnhi8l3D2Qq5+PQNueCVUz6FGBIzRKSzy3djEA3tK3M55
e+wU5t1hTnGinHpOvqBVbJlYiCE/lIewa7sFhAFB+RHQKlMpYcsi3TiOWpKTEAWY
RZlJOQxPU3yWQy9Ikho02ACTH9RktUyYVmwzGHh5QErq7Yk20Y5knSEezKAC31oZ
Jtg+yWkn6Usiho4aBzUmX++RvdDjxzfT/A00XO1oMnOU1+PTUhsmwOgkD1sWdUOy
4uMdQ7ryuMPiDfcvVKdN92+ydeVmEY18ab5HrD1AsfQYev2aFHyYVMIwKjYvm/UN
VckHZxqcj6ItZbJ8qdvcyal9P5ayNRPdi4rWF3o73P6fUsosIXBcEy+DFxbGAtlj
mOieFa7ea9EkBjTDSwDmUD3PBbOW9qIBlutYm5u8BFLwMMYUwHT+PjDC6yoh4d3b
96TRhwU9ZDrm6wgZvclAIaEdi5MaKoX67ZQQ7TIgu1OnjbfDddoWvor3S/3Z2oCk
rsF0tAdS3ZW4T9nd6LuZWbhmKlEhquUSx9jYut9TBkNGt3/4Ts4mvdC3vZ4ibYho
JwCnk3VXPBfXXwEmdxdJIZ21hVzGx55/O9f+ElTPjn/0uGY4HqB4kYSVlZi4lww6
ZN6c1LeuIzZF2kQgq2oki3CYprCzcF00/eLK/nhhoNE9qKUDV4WpqCHateCi0rxZ
j9UhgnnbO8Gajbbr0lteb0W9Y76VUmQi2A7/+pKlewuEHUrIJjb3lIW2mITDExeM
EXbKeUXP+m/Md/MCGGTNtiqXn9voXCQv6iuVt5qVcAhFOUCYKXqH0z+rXoNTuN+I
n8teYkYDLs4kvnBre/23jABVVh9QWVVjL5GDWb6MxZIPls3fQXwmuxSUibIFOCXh
sVWeZpFQJvvJ5nXIXKdBj8UeNbXLAqzQlkEpYt9AZxTA2Ua/0taKOVYIc28DwOCg
UOkLiYRB/BrNxGn02F9w8ooLiZRpBTlhDCkqbvQawdwQEhX8/U14nSQZ2mDs7v9s
pKSw5hmVJ2YSsnV38EawWE2nKfmfVZfOFyrcajh+dN0C+pko1HWYxpJXFLO+95hb
4K+fBxJbQ/ukpASWIDlVfW6ZnRes28J3s4CJ6y7Nabl6oWVMxtc8rpMeBzFI2d49
0w4M/FV7uuDxuvv4llCrk6H7rg3XGGhHwRikkxewnpRx18t23N/62Jr3Jws/VslU
OegEgzwqToLjvZuX6Tg9GndBQAIKEn/fDflKbhfIR0pezFaC8vETfagWw+WkcgDm
3o8ZoVr1lMpc5bhuMTvkL4p18CJzbJy3yEbyEiRYZkcmzM+rKFlxdzTBNGGiaoH5
n8w8hQda6+3L3fl8agGFgigXXtR3r9xSfgzlKJxE8a5CWSERu7PRZcZoWZvxxqdt
T5OKTq9XH/sN2xxrrAsMMxeZAdDbccGQQpXA3rBUhSnZQs+HKkB4+hmlwVJMzDxo
EZOXUESyEjoHI65FRHCPTA11xa5LnVipuUN2zR/st++j32Cgj1eDD5GqYFqz2KB3
3BHN+GK0Fpti/Lvq5oUo4Ks7Rq3ZOESDuBQUhsK0QZf0p6wWC39XYSQXMpNdtLBR
DmUg2+dCl3ZeNii/9EnvlrxGIT9XU+Hf578LEjuSKRqWHTExdp4Gi4zJO7o22z5v
ytTnHbUkye9+CQRCR9JCcjo303JIiQvDq+DyuBf+wAHUfcZeCtMztfYRcUNgsxJl
kSJtOvI7ZrDyRNuDZQIqBI5YH1ne7nHlAuad/dZTfrjautKMVe2fNJwJlIOkMA/9
FhRren8UxFFFHnQJtobnfXNF/DRQy6RvGuO5WGyEZWVisrkFzbGVN2rhyYtPYD84
15tOaBszoS9VNCCcN5mxkfZf0MukuQP6cKvT/gDEHOSvgrrPuOPh9lZ/1IxNNyHf
EuE/6NcaKTqQpaAlG2yP0rddRthD0oE84g2TcMXDJoPPs3el/9H9PBcAGWZ+KVZp
aHwZ6/t03I3zedHpQn+IQF03E2s9qA5m+qo1mRh0CMZ2A8bbG1DDVB1+aaFsSP+e
zyYhe+V7+cR1GyNgh4L4HRWiexKKVyQ2gFMbaaA430Zra5DWIu/7oo+s6BEiFARc
u66HxBP4xjpeMzLzvUYklaugVHI0775jd4vuCmkn0uXer5sDnF9663dF4sZqrEdR
kZ9CHacFkwVgWiQTySPoALM3PAveaBJ3pmxOiSMCi2dWIV42+3tOaag+YIDrO7iz
/yGJIRjf5cNst0+v3u0L+rGcV7yl9WjssT/QMEXa4ysfmPuzV0zDKRi6IQLm3ibT
TLFSBIV2+BKKVHDo5M45/8CafLBDZF1zqu5vTg7DDkSfoPYI32XyuChS8TcLcR82
3O/e0pwAXcSbY5DbYBUwLajap0fTvyuItiKLX3BMtL7vtsEp0E/roZAmrXWxqEbD
nxt2yxI/djUKvMdc9CGhXY6fgRJ2A84LzJ9ufurLUjLHr/tLiPXITkxAi0vSRFb6
2s4Sjzjw7i+OY4SSOxM/Q1aSgaczQCTlrEj4NZq6s3CYObZmW/FepIhpoGBzbN3q
bp5RHzvv2dEkcjClprcPslPKynOpm5dT/Y23Bukrg+qAL00C5tJMdrDBQ6kl+Iah
g+uvAHjuD047dFyEy+33Vtaat+fLu02khNUOYQBg9ep5VjMYF/R21bN/cf37P0rk
oLay99rGqOG/VQQ0bWbkYBQSp7F2RxT/Njuwfnd4KdoxAzBaYrlllo7VhQLDXQ6u
iQVxEucsEUzX7ChBOuw+hvyQicWNkiMqjDzfC1ITGU3dZqP7BuyCfBxP6HFQTy7m
HEtLX7J4XWHJWBO6o1LR3j/s3+XOBsEeuFPbyXwOmgCC+RAsZRwVVGgLA8D8rRH7
thREC7yzshlRqajYg8+eDl+6dJJr+y0gbDon3rsnIKZTyFSNk/+iVIcLkcubiWhj
5vWo04B1kcFkXPwxrgwmDle5Wzl7AlFKT0iU41+S+e9Ec5RcBbzMj/qJWad+iXAa
2IMACsps3NnG/2HbEq938HKgXUNYvornVRKDJvZ2Hd6Jp68Z2it/SDJtt3/l3z3G
7eMxIT8Z6kzKsb6TQPNQ5ZeZGEK+0a45tim5IAELtfDZchVDmgV7inB1s8qEEbPf
cnipjJkpVLda6Odgst+0Rca3lysPnGdbX7iNRw7/EQ4gpcLxWBKoMd1KFLkINs2v
37J4+kP/FR6d6WeNg3JepjkJCs+ycu4ZI4iTineNUDex4uO0rwQlo1phyHIKeqLN
fSY2sSjcI+YrVtPRQfTtSBC1d9ZXlXJXmo3hsdPYS95tGYSmI32vMlP29yu/ig/O
hf5ghdgdHoLGtmwtFr8PqIfu6qE8WzBm6aGsSXYzpvMTSOZJNveIq06wcotSZhJc
Pd17cvGUQAhH6ybwZj4wA7Bepvj4IccQUEt8sfeskeJjx6QVxI9471ZyHCevmD7F
fi5GrSRiuDYtD56Rnnb+nhr47jzshUGkxSh50iQV28i+cgDkG5HDMmKEkVzlUzc9
JzNvlmEfB+++XbdKMAh+yH/6teKDoUF4rHLJ3C4yuaxQoZj93Hb2FGZ5iFSbQF6j
Kp4V2ks9sgxrDF/TEdO/6sTrjluMcBNVjtSKuV2L5fxtnY+awKXhk/u9E28fwlvt
iVYVdwP9lsHhiXZ0/h7+kCmfBgBOA1lukMxSP7E6pgiWtHRhaTFDu9EgvqaUFKMw
R4ZoGVDl/p4MdNMxHiwAOkv/vynUvEs/B68+5i9ffx+DmD6VaMHeywiAmDmKFq7p
7+WguFMj0tDTVqKf8mYa/cGdDYpcNhQFE16AoEMCqfNZDF/eQ+MYh6XuWIQxSvTX
7iQqvOMLNGiA0ipY+eXORoGOxR4Se5ESGnKUwROjUqMywB0Let/L3ZzdWf4HZk9Y
S0TjtY+w05qdfS0PsW9ngAGjsKcN6pjzObVI1h39QJcZafgHws0iJtaUjG3PwCdg
yO+OEbH5eZcsQTXfj37TJiFM6hYQtglEt75EF8ta5xAR8JG/eq+yOWkco9gGJMAQ
wajHqVEs5RSjXJqbaAll+2UhtX0CUagFgvTUZAtEoGeEyRAuMTeTBqGq7bluwYnb
c4tqArLQvc+xivZbHINbhsKvaj02rtn8ZbVc+bwf1TIji1V/Ad5B5bgDw85llJXA
uHSWIqIFaciXesINtbvhSXQISNqynzqWiYmV5Y9ytTQ1oIgEkBTA9Yus61MrM1hk
4O75FV6MjpHX3ufr7AAoO1qUl+Dn8gSD6BQvRldvwBA+f7jb5ucNIl7rLTqgAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHERodIyouMQ==
-----END CERTIFICATE-----
`

var mldsa44Tests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{MLDSA44Sig, mldsa44CertPem},
}

var mldsa65Tests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{MLDSA65Sig, mldsa65CertPem},
}

var mldsa87Tests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{MLDSA87Sig, mldsa87CertPem},
}

func TestMLDSA44(t *testing.T) {
	for i, test := range mldsa44Tests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*mldsa44.PublicKey); !ok {
			t.Errorf("%d: wanted a MLDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != MLDSA44 {
			t.Errorf("%d: public key algorithm is %v, want MLDSA44", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

func TestMLDSA65(t *testing.T) {
	for i, test := range mldsa65Tests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*mldsa65.PublicKey); !ok {
			t.Errorf("%d: wanted a MLDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != MLDSA65 {
			t.Errorf("%d: public key algorithm is %v, want MLDSA65", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

func TestMLDSA87(t *testing.T) {
	for i, test := range mldsa87Tests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*mldsa87.PublicKey); !ok {
			t.Errorf("%d: wanted a MLDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != MLDSA87 {
			t.Errorf("%d: public key algorithm is %v, want MLDSA87", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

var ed25519CertPem = `-----BEGIN CERTIFICATE-----
MIIBFTCByKADAgECAghNZYIhB/z9UjAFBgMrZXAwDzENMAsGA1UEAxMEcm9vdDAe
Fw0xNzAyMTIxOTQ5NDVaFw0xNzAyMTMxOTQ5NDVaMA8xDTALBgNVBAMTBHJvb3Qw
KjAFBgMrZXADIQB1mSjGpYU8nliw5Ah7Uq6pElOk/QofMn476Lr4CII0zKNCMEAw
DgYDVR0PAQH/BAQDAgKEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKeTKKir
Wabr+CP52M0stAf7KInwMAUGAytlcANBAFRwyNSg/F3Zfeqiptn99pbeQsoIApvb
zKfb2zXCmF6OdhUSWrtHFY0y5rsCo1ha7cQQttRjOGiuKSKkjkmzHAg=
-----END CERTIFICATE-----`
var x25519CertPem = `-----BEGIN CERTIFICATE-----
MIIBTDCB/6ADAgECAgh4YpoPXz8WTzAFBgMrZXAwDzENMAsGA1UEAxMEcm9vdDAe
Fw0xNzAyMTIxOTQ5NDVaFw0xNzAyMTMxOTQ5NDVaMBMxETAPBgNVBAMTCHRlc3Qu
Y29tMCowBQYDK2VuAyEAFKwi3LTY6apEQDNMrx2WagCHpGVFL7tIB/uTwzoyUiCj
dTBzMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMB
Af8EAjAAMB0GA1UdDgQWBBQG9I1UYG2pAHSs6nYKQFo/YTAkpTAfBgNVHSMEGDAW
gBSnkyioq1mm6/gj+djNLLQH+yiJ8DAFBgMrZXADQQBbuoByEYlgzxTskoUtCwBo
dVaJPEZmR+AHGHAFcBTEISEK5sl6h9Z923i6xMwHTjWbYw3JYwqeuJUfm3qCncQL
-----END CERTIFICATE-----`
var ed25519Tests = []struct {
	sigAlgo    SignatureAlgorithm
	pemCert    string
	signerCert string
}{
	{Ed25519Sig, ed25519CertPem, ed25519CertPem},
}

func Test25519(t *testing.T) {
	for i, test := range ed25519Tests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		pemBlock, _ = pem.Decode([]byte(test.signerCert))
		signerCert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
			t.Errorf("%d: wanted an Ed25519 public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != Ed25519 {
			t.Errorf("%d: public key algorithm is %v, want Ed25519", i, pka)
		}
		if err = cert.CheckSignatureFrom(signerCert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

var x25519Tests = []struct {
	sigAlgo    SignatureAlgorithm
	pemCert    string
	signerCert string
}{
	{Ed25519Sig, x25519CertPem, ed25519CertPem},
}

func TestX25519(t *testing.T) {
	for i, test := range x25519Tests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		pemBlock, _ = pem.Decode([]byte(test.signerCert))
		signerCert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(X25519PublicKey); !ok {
			t.Errorf("%d: wanted an Ed25519 public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != X25519 {
			t.Errorf("%d: public key algorithm is %v, want Ed25519", i, pka)
		}
		if err = cert.CheckSignatureFrom(signerCert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

// Self-signed certificate using DSA with SHA1
var dsaCertPem = `-----BEGIN CERTIFICATE-----
MIIEDTCCA82gAwIBAgIJALHPghaoxeDhMAkGByqGSM44BAMweTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAk5DMQ8wDQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2ds
ZSwgSW5jMRIwEAYDVQQDEwlKb24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFs
bGllQGdvb2dsZS5jb20wHhcNMTEwNTE0MDMwMTQ1WhcNMTEwNjEzMDMwMTQ1WjB5
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCTkMxDzANBgNVBAcTBk5ld3RvbjEUMBIG
A1UEChMLR29vZ2xlLCBJbmMxEjAQBgNVBAMTCUpvbiBBbGxpZTEiMCAGCSqGSIb3
DQEJARYTam9uYWxsaWVAZ29vZ2xlLmNvbTCCAbcwggEsBgcqhkjOOAQBMIIBHwKB
gQC8hLUnQ7FpFYu4WXTj6DKvXvz8QrJkNJCVMTpKAT7uBpobk32S5RrPKXocd4gN
8lyGB9ggS03EVlEwXvSmO0DH2MQtke2jl9j1HLydClMf4sbx5V6TV9IFw505U1iW
jL7awRMgxge+FsudtJK254FjMFo03ZnOQ8ZJJ9E6AEDrlwIVAJpnBn9moyP11Ox5
Asc/5dnjb6dPAoGBAJFHd4KVv1iTVCvEG6gGiYop5DJh28hUQcN9kul+2A0yPUSC
X93oN00P8Vh3eYgSaCWZsha7zDG53MrVJ0Zf6v/X/CoZNhLldeNOepivTRAzn+Rz
kKUYy5l1sxYLHQKF0UGNCXfFKZT0PCmgU+PWhYNBBMn6/cIh44vp85ideo5CA4GE
AAKBgFmifCafzeRaohYKXJgMGSEaggCVCRq5xdyDCat+wbOkjC4mfG01/um3G8u5
LxasjlWRKTR/tcAL7t0QuokVyQaYdVypZXNaMtx1db7YBuHjj3aP+8JOQRI9xz8c
bp5NDJ5pISiFOv4p3GZfqZPcqckDt78AtkQrmnal2txhhjF6o4HeMIHbMB0GA1Ud
DgQWBBQVyyr7hO11ZFFpWX50298Sa3V+rzCBqwYDVR0jBIGjMIGggBQVyyr7hO11
ZFFpWX50298Sa3V+r6F9pHsweTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMQ8w
DQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2dsZSwgSW5jMRIwEAYDVQQDEwlK
b24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFsbGllQGdvb2dsZS5jb22CCQCx
z4IWqMXg4TAMBgNVHRMEBTADAQH/MAkGByqGSM44BAMDLwAwLAIUPtn/5j8Q1jJI
7ggOIsgrhgUdjGQCFCsmDq1H11q9+9Wp9IMeGrTSKHIM
-----END CERTIFICATE-----
`

func TestParseCertificateWithDsaPublicKey(t *testing.T) {
	expectedKey := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: bigFromHexString("00BC84B52743B169158BB85974E3E832AF5EFCFC42B264349095313A4A013EEE069A1B937D92E51ACF297A1C77880DF25C8607D8204B4DC45651305EF4A63B40C7D8C42D91EDA397D8F51CBC9D0A531FE2C6F1E55E9357D205C39D395358968CBEDAC11320C607BE16CB9DB492B6E78163305A34DD99CE43C64927D13A0040EB97"),
			Q: bigFromHexString("009A67067F66A323F5D4EC7902C73FE5D9E36FA74F"),
			G: bigFromHexString("009147778295BF5893542BC41BA806898A29E43261DBC85441C37D92E97ED80D323D44825FDDE8374D0FF15877798812682599B216BBCC31B9DCCAD527465FEAFFD7FC2A193612E575E34E7A98AF4D10339FE47390A518CB9975B3160B1D0285D1418D0977C52994F43C29A053E3D685834104C9FAFDC221E38BE9F3989D7A8E42"),
		},
		Y: bigFromHexString("59A27C269FCDE45AA2160A5C980C19211A820095091AB9C5DC8309AB7EC1B3A48C2E267C6D35FEE9B71BCBB92F16AC8E559129347FB5C00BEEDD10BA8915C90698755CA965735A32DC7575BED806E1E38F768FFBC24E41123DC73F1C6E9E4D0C9E692128853AFE29DC665FA993DCA9C903B7BF00B6442B9A76A5DADC6186317A"),
	}
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.PublicKeyAlgorithm != DSA {
		t.Errorf("Parsed key algorithm was not DSA")
	}
	parsedKey, ok := cert.PublicKey.(*dsa.PublicKey)
	if !ok {
		t.Fatalf("Parsed key was not a DSA key: %s", err)
	}
	if expectedKey.Y.Cmp(parsedKey.Y) != 0 ||
		expectedKey.P.Cmp(parsedKey.P) != 0 ||
		expectedKey.Q.Cmp(parsedKey.Q) != 0 ||
		expectedKey.G.Cmp(parsedKey.G) != 0 {
		t.Fatal("Parsed key differs from expected key")
	}
}

func TestParseCertificateWithDSASignatureAlgorithm(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.SignatureAlgorithm != DSAWithSHA1 {
		t.Errorf("Parsed signature algorithm was not DSAWithSHA1")
	}
}

func TestVerifyCertificateWithDSASignature(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	// test cert is self-signed
	if err = cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("DSA Certificate verification failed: %s", err)
	}
}

const pemCertPolicyUserNotices = `-----BEGIN CERTIFICATE-----
MIIEiTCCA3GgAwIBAgIUMYpvK6wyDbRymJE+DvP7moEyrzYwDQYJKoZIhvcNAQEL
BQAwgZUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNSTESMBAGA1UEBwwJQW5uIEFy
Ym9yMQ8wDQYDVQQKDAZDZW5zeXMxDzANBgNVBAsMBkNlbnN5czEPMA0GA1UEAwwG
Q2Vuc3lzMTIwMAYJKoZIhvcNAQkBFiNhYnNvbHV0ZWx5bm90eW91cmJ1c2luZXNz
QGNlbnN5cy5pbzAeFw0yMjA1MDUxNzQxMjBaFw0yMjA2MDQxNzQxMjBaMIGVMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCTUkxEjAQBgNVBAcMCUFubiBBcmJvcjEPMA0G
A1UECgwGQ2Vuc3lzMQ8wDQYDVQQLDAZDZW5zeXMxDzANBgNVBAMMBkNlbnN5czEy
MDAGCSqGSIb3DQEJARYjYWJzb2x1dGVseW5vdHlvdXJidXNpbmVzc0BjZW5zeXMu
aW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0zShNJeZsIR/aZNS1
TDTLbx61Y2qkllUzr+Lh47/SQAw4c2jdJB/yAdqEIWXPgmvlegYb+0XJRz1FeUBU
A8mzStDVPgfmW9vJksdPdp5yBoxodpBJ5NA5Ez+S3+znJL6F4vH+orgOO2D+ah4E
9qybSxVXjKxWGTjqKvKJOohRi9VxaGNVvJbvg2K+HtgEl7J7nkJfT+a4yIsM086U
e0p/ZzxNLummTwrZmEmD78HnrEIg91m2vb/I9QJvGtLnZDBp2TdeqKh0ihmadldG
w8hXYr25hh1TQQLxi7F3b22LQexRsg/GKDKAVu2HQL9V8Qty97RExPRdLDJDAFVK
XzwXAgMBAAGjgc4wgcswgcgGA1UdIASBwDCBvTAFBgMqAwQwBQYDLQYHMIGsBgMr
BQcwgaQwEAYIKwYBBQUHAgEWBHVybDEwEAYIKwYBBQUHAgEWBHVybDIwQQYIKwYB
BQUHAgIwNTArFht0aGUgbWluaXN0cnkgb2Ygc2lsbHkgd2Fsa3MwDAIBAQIBAgIB
AwIBBBoGZm9vYmFyMBQGCCsGAQUFBwICMAgaBmZvb2JhejAlBggrBgEFBQcCAjAZ
MBcWEGFwZXJ0dXJlIHNjaWVuY2UwAwIBKjANBgkqhkiG9w0BAQsFAAOCAQEAxXVD
/1kBp1ro5EfPGxiDscjQ7cOJBVUdbLMfqQzXmBLzFnJUj0DryyeUZsMHIw8PMctr
NUR6rrNWFX0IQENOJIwFjHv0X1gih1dJcohBcgaT8SNCCcZsGImEqdFZlL6mgwtI
K4YBIAde0Jl0Kwrk+6CdR1/tlXN0PegycogBvfItSXwKkKvjkIKGy7A9g6+MWtMg
DcOdH/BxukeT6hfvOAI5r6eFMkpbK/tL2RuygdMk9hIwqnJ3E/SjTRs8jkEACZ2y
PXbTZ4ymfTyPXCwA8szaFzz/LXJ7yak1YzDqyAh7fTN+om9mBcmciDoz6+JV027o
0/KLWM5xP8R3VbSbYQ==
-----END CERTIFICATE-----`

func assertUserNoticeEqual(t *testing.T, n1, n2 UserNotice) {

	assert.Equal(t, n1.ExplicitText, n2.ExplicitText)

	if (n1.NoticeReference == nil) != (n2.NoticeReference == nil) {
		return
	}

	if n1.NoticeReference != nil {
		r1 := *n1.NoticeReference
		r2 := *n2.NoticeReference
		assert.Equal(t, r1.Organization, r2.Organization)
		assert.Equal(t, r1.NoticeNumbers, r2.NoticeNumbers)
	}
}

// TestCertificatePolicyUserNotices ensures that the UserNotices field of
// the CertificatePolicies extension are parsed correctly, using an example
// certificate with an unorthodox usage of the extension.
func TestCertificatePolicyUserNotices(t *testing.T) {
	block, _ := pem.Decode([]byte(pemCertPolicyUserNotices))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("couldn't parse test cert %s", err.Error())
	}

	if !assert.Len(t, cert.UserNotices, 3) {
		return
	}

	if !assert.Len(t, cert.UserNotices[2], 3) {
		return
	}

	e1 := "foobar"
	e2 := "foobaz"

	p1 := UserNotice{
		ExplicitText: &e1,
		NoticeReference: &NoticeReference{
			Organization:  "the ministry of silly walks",
			NoticeNumbers: []int{1, 2, 3, 4},
		},
	}

	p2 := UserNotice{
		ExplicitText:    &e2,
		NoticeReference: nil,
	}

	p3 := UserNotice{
		NoticeReference: &NoticeReference{
			Organization:  "aperture science",
			NoticeNumbers: []int{42},
		},
	}

	assertUserNoticeEqual(t, p1, cert.UserNotices[2][0])
	assertUserNoticeEqual(t, p2, cert.UserNotices[2][1])
	assertUserNoticeEqual(t, p3, cert.UserNotices[2][2])
}

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIB5DCCAZCgAwIBAgIBATALBgkqhkiG9w0BAQUwLTEQMA4GA1UEChMHQWNtZSBDbzEZMBcGA1UE
AxMQdGVzdC5leGFtcGxlLmNvbTAeFw03MDAxMDEwMDE2NDBaFw03MDAxMDIwMzQ2NDBaMC0xEDAO
BgNVBAoTB0FjbWUgQ28xGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wWjALBgkqhkiG9w0BAQED
SwAwSAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0fd7Ai2KW5ToIwzFo
fvJcS/STa6HA5gQenRUCAwEAAaOBnjCBmzAOBgNVHQ8BAf8EBAMCAAQwDwYDVR0TAQH/BAUwAwEB
/zANBgNVHQ4EBgQEAQIDBDAPBgNVHSMECDAGgAQBAgMEMBsGA1UdEQQUMBKCEHRlc3QuZXhhbXBs
ZS5jb20wDwYDVR0gBAgwBjAEBgIqAzAqBgNVHR4EIzAhoB8wDoIMLmV4YW1wbGUuY29tMA2CC2V4
YW1wbGUuY29tMAsGCSqGSIb3DQEBBQNBAHKZKoS1wEQOGhgklx4+/yFYQlnqwKXvar/ZecQvJwui
0seMQnwBhwdBkHfVIU2Fu5VUMRyxlf0ZNaDXcpU581k=
-----END CERTIFICATE-----`

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, _ := ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	cert, _ := ParseCertificate(block.Bytes)

	now := time.Unix(1000, 0)
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: now,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: now,
		},
	}

	crlBytes, err := cert.CreateCRL(rand.Reader, priv, revokedCerts, now, expiry)
	if err != nil {
		t.Errorf("error creating CRL: %s", err)
	}

	_, err = ParseDERCRL(crlBytes)
	if err != nil {
		t.Errorf("error reparsing CRL: %s", err)
	}
}

func fromBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		panic("failed to base64 decode")
	}
	return out[:n]
}

func TestParseDERCRL(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestCRLWithoutExpiry(t *testing.T) {
	derBytes := fromBase64("MIHYMIGZMAkGByqGSM44BAMwEjEQMA4GA1UEAxMHQ2FybERTUxcNOTkwODI3MDcwMDAwWjBpMBMCAgDIFw05OTA4MjIwNzAwMDBaMBMCAgDJFw05OTA4MjIwNzAwMDBaMBMCAgDTFw05OTA4MjIwNzAwMDBaMBMCAgDSFw05OTA4MjIwNzAwMDBaMBMCAgDUFw05OTA4MjQwNzAwMDBaMAkGByqGSM44BAMDLwAwLAIUfmVSdjP+NHMX0feW+aDU2G1cfT0CFAJ6W7fVWxjBz4fvftok8yqDnDWh")
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certList.TBSCertList.NextUpdate.IsZero() {
		t.Errorf("NextUpdate is not the zero value")
	}
}

func TestParsePEMCRL(t *testing.T) {
	pemBytes := fromBase64(pemCRLBase64)
	certList, err := ParseCRL(pemBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 2
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestImports(t *testing.T) {
	switch runtime.GOOS {
	case "android", "nacl":
		t.Skipf("skipping on %s", runtime.GOOS)
	}

	if err := exec.Command("go", "run", "x509_test_import.go").Run(); err != nil {
		t.Errorf("failed to run x509_test_import.go: %s", err)
	}
}

const derCRLBase64 = "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"

const pemCRLBase64 = "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tDQpNSUlCOWpDQ0FWOENBUUV3RFFZSktvWklodmNOQVFFRkJRQXdiREVhTUJnR0ExVUVDaE1SVWxOQklGTmxZM1Z5DQphWFI1SUVsdVl5NHhIakFjQmdOVkJBTVRGVkpUUVNCUWRXSnNhV01nVW05dmRDQkRRU0IyTVRFdU1Dd0dDU3FHDQpTSWIzRFFFSkFSWWZjbk5oYTJWdmJuSnZiM1J6YVdkdVFISnpZWE5sWTNWeWFYUjVMbU52YlJjTk1URXdNakl6DQpNVGt5T0RNd1doY05NVEV3T0RJeU1Ua3lPRE13V2pDQmpEQktBaEVBckRxb2g5RkhKSFhUN09QZ3V1bjQrQmNODQpNRGt4TVRBeU1UUXlOekE1V2pBbU1Bb0dBMVVkRlFRRENnRUpNQmdHQTFVZEdBUVJHQTh5TURBNU1URXdNakUwDQpNalExTlZvd1BnSVJBTEd6blowOTVQQjVhQU9MUGc1N2ZNTVhEVEF5TVRBeU16RTBOVEF4TkZvd0dqQVlCZ05WDQpIUmdFRVJnUE1qQXdNakV3TWpNeE5EVXdNVFJhb0RBd0xqQWZCZ05WSFNNRUdEQVdnQlQxVERGNlVRTS9MTmVMDQpsNWx2cUhHUXEzZzltekFMQmdOVkhSUUVCQUlDQUlRd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQUZVNUFzNk16DQpxNVBSc2lmYW9iUVBHaDFhSkx5QytNczVBZ2MwYld5QTNHQWR4dXI1U3BQWmVSV0NCamlQL01FSEJXSkNsQkhQDQpHUmNxNXlJZDNFakRrYUV5eFJhK2k2N0x6dmhJNmMyOUVlNks5cFNZd2ppLzdSVWhtbW5Qclh0VHhsTDBsckxyDQptUVFKNnhoRFJhNUczUUE0Q21VZHNITnZicnpnbUNZcHZWRT0NCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0NCg0K"

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %s", err)
	}

	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	_, mldsa44Priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA44 key: %s", err)
	}

	_, mldsa65Priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA65 key: %s", err)
	}

	_, mldsa87Priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate MLDSA87 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    interface{}
		sigAlgo SignatureAlgorithm
	}{
		{"RSA", rsaPriv, SHA1WithRSA},
		{"ECDSA-256", ecdsa256Priv, ECDSAWithSHA1},
		{"ECDSA-384", ecdsa384Priv, ECDSAWithSHA1},
		{"ECDSA-521", ecdsa521Priv, ECDSAWithSHA1},
		{"MLDSA44", mldsa44Priv, MLDSA44Sig},
		{"MLDSA65", mldsa65Priv, MLDSA65Sig},
		{"MLDSA87", mldsa87Priv, MLDSA87Sig},
	}

	for _, test := range tests {
		template := CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func marshalAndParseCSR(t *testing.T, template *CertificateRequest) *CertificateRequest {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	derBytes, err := CreateCertificateRequest(rand.Reader, template, rsaPriv)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidExtensionSubjectAltName,
				Value: sanContents,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.DNSNames)
	}

	// If there is already an attribute with X.509 extensions then the
	// extra extensions should be added to it rather than creating a CSR
	// with two extension attributes.

	template.Attributes = []pkix.AttributeTypeAndValueSET{
		{
			Type: oidExtensionRequest,
			Value: [][]pkix.AttributeTypeAndValue{
				{
					{
						Type:  oidExtensionAuthorityInfoAccess,
						Value: []byte("foo"),
					},
				},
			},
		},
	}

	csr = marshalAndParseCSR(t, &template)
	if l := len(csr.Attributes); l != 1 {
		t.Errorf("incorrect number of attributes: %d\n", l)
	}

	if !csr.Attributes[0].Type.Equal(oidExtensionRequest) ||
		len(csr.Attributes[0].Value) != 1 ||
		len(csr.Attributes[0].Value[0]) != 2 {
		t.Errorf("bad attributes: %#v\n", csr.Attributes)
	}

	sanContents2, err := marshalSANs([]string{"foo2.example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Extensions in Attributes should override those in ExtraExtensions.
	template.Attributes[0].Value[0] = append(template.Attributes[0].Value[0], pkix.AttributeTypeAndValue{
		Type:  oidExtensionSubjectAltName,
		Value: sanContents2,
	})

	csr = marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo2.example.com" {
		t.Errorf("Attributes did not override ExtraExtensions. Got %v\n", csr.DNSNames)
	}
}

func TestParseCertificateRequest(t *testing.T) {
	csrBytes := fromBase64(csrBase64)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "gopher@golang.org" {
		t.Errorf("incorrect email addresses found: %v", csr.EmailAddresses)
	}

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
		t.Errorf("incorrect DNS names found: %v", csr.DNSNames)
	}

	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
		t.Errorf("incorrect Subject name: %v", csr.Subject)
	}

	found := false
	for _, e := range csr.Extensions {
		if e.Id.Equal(oidExtensionBasicConstraints) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("basic constraints extension not found in CSR")
	}
}

func TestMaxPathLen(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %s", err)
	}

	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	serialiseAndParse := func(template *Certificate) *Certificate {
		derBytes, err := CreateCertificate(rand.Reader, template, template, &rsaPriv.PublicKey, rsaPriv)
		if err != nil {
			t.Fatalf("failed to create certificate: %s", err)
			return nil
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Fatalf("failed to parse certificate: %s", err)
			return nil
		}

		return cert
	}

	cert1 := serialiseAndParse(template)
	if m := cert1.MaxPathLen; m != -1 {
		t.Errorf("Omitting MaxPathLen didn't turn into -1, got %d", m)
	}
	if cert1.MaxPathLenZero {
		t.Errorf("Omitting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 1
	cert2 := serialiseAndParse(template)
	if m := cert2.MaxPathLen; m != 1 {
		t.Errorf("Setting MaxPathLen didn't work. Got %d but set 1", m)
	}
	if cert2.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	cert3 := serialiseAndParse(template)
	if m := cert3.MaxPathLen; m != 0 {
		t.Errorf("Setting MaxPathLenZero didn't work, got %d", m)
	}
	if !cert3.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen to zero didn't result in MaxPathLenZero")
	}
}

// This CSR was generated with OpenSSL:
//
//	openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key -config openssl.cnf
//
// The openssl.cnf needs to include this section:
//
//	[ v3_req ]
//	basicConstraints = CA:FALSE
//	keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//	subjectAltName = email:gopher@golang.org,DNS:test.example.com
const csrBase64 = "MIIC4zCCAcsCAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOY+MVedRg2JEnyeLcSzcsMv2VcsTfkB5+Etd6hihAh6MrGezNyASMMKuQN6YhCX1icQDiQtGsDLTtheNnSXK06tAhHjAP/hGlszRJp+5+rP2M58fDBAkUBEhskbCUWwpY14jFtVuGNJ8vF8h8IeczdolvQhX9lVai9G0EUXJMliMKdjA899H0mRs9PzHyidyrXFNiZlQXfD8Kg7gETn2Ny965iyI6ujAIYSCvam6TnxRHYH2MBKyVGvsYGbPYUQJCsgdgyajEg6ekihvQY3SzO1HSAlZAd7d1QYO4VeWJ2mY6Wu3Jpmh+AmG19S9CcHqGjd0bhuAX9cpPOKgnEmqn0CAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEFBQADggEBAC9+QpKfdabxwCWwf4IEe1cKjdXLS1ScSuw27a3kZzQiPV78WJMa6dB8dqhdH5BRwGZ/qsgLrO6ZHlNeIv2Ib41Ccq71ecHW/nXc94A1BzJ/bVdI9LZcmTUvR1/m1jCpN7UqQ0ml1u9VihK7Pe762hEYxuWDQzYEU0l15S/bXmqeq3eF1A59XT/2jwe5+NV0Wwf4UQlkTXsAQMsJ+KzrQafd8Qv2A49o048uRvmjeJDrXLawGVianZ7D5A6Fpd1rZh6XcjqBpmgLw41DRQWENOdzhy+HyphKRv1MlY8OLkNqpGMhu8DdgJVGoT16DGiickoEa7Z3UCPVNgdTkT9jq7U="

const sanManyOtherName = "MEmgEAYIKwYBBAHZWy6gBAICAc2CCHRlc3QuZ292oA8GCCsGAQQB2VsuoAMCASqCB2dvdi5nb3agEQYIKwYBBAHZWy6gBQIDAXUA"

func TestParseGeneralNamesOtherName(t *testing.T) {
	sanMultipleOther := fromBase64(sanManyOtherName)
	otherNames, dnsNames, emailAddresses, URIs, directoryNames, ediPartyNames, ipAddresses, registeredIDs, _, err := parseGeneralNames(sanMultipleOther)

	if err != nil {
		t.Errorf("parseGeneralNames returned error %v", err)
	}
	if emailAddresses != nil || directoryNames != nil || URIs != nil || ediPartyNames != nil || ipAddresses != nil || registeredIDs != nil {
		t.Errorf("parseGeneralNames returned unexpected name type from sanManyOtherName")
	}
	if len(dnsNames) != 2 || dnsNames[0] != "test.gov" || dnsNames[1] != "gov.gov" {
		t.Errorf("parseGeneralNames returned unexpected dnsNames from sanManyOtherName: %v", dnsNames)
	}
	if len(otherNames) != 3 {
		t.Errorf("parseGeneralNames returned unexpected # of otherName in sanManyOtherName: %v (expected 3)", len(otherNames))
	}
	var otherInts [3]int
	var expectedInts [3]int = [3]int{461, 42, 95488}
	for x := 0; x < 3; x++ {
		rest, err := asn1.Unmarshal(otherNames[x].Value.Bytes, &(otherInts[x]))
		if err != nil {
			t.Errorf("unexpected error in unmarshaling otherName %v", err)
		}
		if len(rest) != 0 {
			t.Errorf("unexpected extra bytes in otherName")
		}
	}
	for i := range otherInts {
		if otherInts[i] != expectedInts[i] {
			t.Errorf("otherName contained unexpected value %v, expected %v", otherInts[i], expectedInts[i])
		}
	}

}

const sanManyDirectoryName = "MIHtpBwwGjEYMBYGA1UEChMPRXh0cmVtZSBEaXNjb3JkgggqLmdvdi51c6SBnDCBmTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkZMMRQwEgYDVQQHEwtUYWxsYWhhc3NlZTEcMBoGA1UECRMTMzIxMCBIb2xseSBNaWxsIFJ1bjEOMAwGA1UEERMFMzAwNjIxGDAWBgNVBAoTD0V4dHJlbWUgRGlzY29yZDEOMAwGA1UECxMFQ2hhb3MxDzANBgNVBAMTBmdvdi51c4IGZ292LnVzpBwwGjEYMBYGA1UEChMPRXh0cmVtZSBEaXNjb3Jk"

func TestParseGeneralNamesDirectoryName(t *testing.T) {
	// TODO: This needs to test that we can parse a GeneralName that contains a
	// DirectoryName, not that we can parse DirectoryNames correctly, which is
	// what it was previously doing. DirectoryName parsing falls under pkix.Name,
	// and should be tested in the pkix package.
}

const sanManyURI = "MF6GGGh0dHA6Ly9nb3YudXMvaW5kZXguaHRtbIIIKi5nb3YudXOGE2h0dHA6Ly9nb3YudXMvaG9tZS+CBmdvdi51c4YbaHR0cDovL2dvdi51cy9ob21lL2NhcGl0b2wv"

func TestParseGeneralNamesUniformResourceIdentifier(t *testing.T) {
	sanMultipleURI := fromBase64(sanManyURI)
	otherNames, dnsNames, emailAddresses, URIs, directoryNames, ediPartyNames, ipAddresses, registeredIDs, _, err := parseGeneralNames(sanMultipleURI)

	if err != nil {
		t.Errorf("parseGeneralNames returned error %v", err)
	}
	if emailAddresses != nil || otherNames != nil || directoryNames != nil || ediPartyNames != nil || ipAddresses != nil || registeredIDs != nil {
		t.Errorf("parseGeneralNames returned unexpected name type from sanManyURI")
	}
	if len(dnsNames) != 2 || dnsNames[0] != "*.gov.us" || dnsNames[1] != "gov.us" {
		t.Errorf("parseGeneralNames returned unexpected dnsNames from sanManyURI: %v", dnsNames)
	}
	if len(URIs) != 3 {
		t.Errorf("parseGeneralNames returned unexpected # of uniformResourceIdentifier in sanManyURI: %v (expected 3)", len(URIs))
	}

	var expectedNames [3]string = [3]string{"http://gov.us/index.html", "http://gov.us/home/", "http://gov.us/home/capitol/"}
	for i := range URIs {
		if URIs[i] != expectedNames[i] {
			t.Errorf("uniformResourceIdentifier contained unexpected value %v, expected %v", URIs[i], expectedNames[i])
		}
	}
}

const sanManyRegisteredID = "MDGICCsGAQUFBw0Bggh0ZXN0LmdvdogIKwYBBAHZWyqCB2dvdi5nb3aICCsGAQUFBw0D"

func TestParseGeneralNamesRegisteredID(t *testing.T) {
	sanMultipleRID := fromBase64(sanManyRegisteredID)
	otherNames, dnsNames, emailAddresses, URIs, directoryNames, ediPartyNames, ipAddresses, registeredIDs, _, err := parseGeneralNames(sanMultipleRID)

	if err != nil {
		t.Errorf("parseGeneralNames returned error %v", err)
	}
	if emailAddresses != nil || otherNames != nil || directoryNames != nil || ediPartyNames != nil || ipAddresses != nil || URIs != nil {
		t.Errorf("parseGeneralNames returned unexpected name type from sanManyRegisteredID")
	}
	if len(dnsNames) != 2 || dnsNames[0] != "test.gov" || dnsNames[1] != "gov.gov" {
		t.Errorf("parseGeneralNames returned unexpected dnsNames from sanManyRegisteredID: %v", dnsNames)
	}
	if len(registeredIDs) != 3 {
		t.Errorf("parseGeneralNames returned unexpected # of registeredIDs in sanManyRegisteredID: %v (expected 3)", len(registeredIDs))
	}

	var expectedNames [3]asn1.ObjectIdentifier = [3]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 13, 1}, {1, 3, 6, 1, 4, 1, 11483, 42}, {1, 3, 6, 1, 5, 5, 7, 13, 3}}
	for i := range registeredIDs {
		if !registeredIDs[i].Equal(expectedNames[i]) {
			t.Errorf("registeredID contained unexpected value %v, expected %v", registeredIDs[i], expectedNames[i])
		}
	}
}

const sanManyEDI = "MIGjpRigBwwFRWFydGihDQwLVW5kZXJncm91bmSCCHRlc3QuZ292pQ6hDBMKZ292ZXJubWVudKUNoQsMCXNvdmVyZWlnboIHZ292LmdvdqUjoAoTCHVuaXZlcnNloRUME1N1cHJlbWUgTGVnaXNsYXR1cmWBDWFkbWluQGdvdi5nb3alIaAKEwh1bml2ZXJzZaETExFTdXByZW1lIEV4ZWN1dGl2ZQ=="

func TestParseGeneralNamesEDIPartyName(t *testing.T) {
	sanMultipleEDI := fromBase64(sanManyEDI)
	otherNames, dnsNames, emailAddresses, URIs, directoryNames, ediPartyNames, ipAddresses, registeredIDs, _, err := parseGeneralNames(sanMultipleEDI)

	if err != nil {
		t.Errorf("parseGeneralNames returned error %v", err)
	}
	if registeredIDs != nil || otherNames != nil || directoryNames != nil || ipAddresses != nil || URIs != nil {
		t.Errorf("parseGeneralNames returned unexpected name type from sanManyEDI")
	}
	if len(dnsNames) != 2 || dnsNames[0] != "test.gov" || dnsNames[1] != "gov.gov" {
		t.Errorf("parseGeneralNames returned unexpected dnsNames from sanManyEDI: %v (expected 2)", dnsNames)
	}
	if len(emailAddresses) != 1 || emailAddresses[0] != "admin@gov.gov" {
		t.Errorf("parseGeneralNames returned unexpected rfc822Names from sanManyEDI: %v", emailAddresses)
	}
	if len(ediPartyNames) != 5 {
		t.Errorf("parseGeneralNames returned unexpected # of ediPartyNames in sanManyEDI: %v (expected 5)", len(ediPartyNames))
	}

	var expectedNames [5]pkix.EDIPartyName
	expectedNames[0] = pkix.EDIPartyName{NameAssigner: "Earth", PartyName: "Underground"}
	expectedNames[1] = pkix.EDIPartyName{PartyName: "government"}
	expectedNames[2] = pkix.EDIPartyName{PartyName: "sovereign"}
	expectedNames[3] = pkix.EDIPartyName{NameAssigner: "universe", PartyName: "Supreme Legislature"}
	expectedNames[4] = pkix.EDIPartyName{NameAssigner: "universe", PartyName: "Supreme Executive"}

	for i := range ediPartyNames {
		if !reflect.DeepEqual(ediPartyNames[i], expectedNames[i]) {
			t.Errorf("ediPartyName contained unexpected value %v, expected %v", ediPartyNames[i], expectedNames[i])
		}
	}
}

const sanAllSuported = "MIGXiAkrBgEEAdlbgzqkHDAaMRgwFgYDVQQKEw9FeHRyZW1lIERpc2NvcmSgEQYIKwYBBAHZWy6gBQIDCCoJpR6gDxMNTW90aGVyIE5hdHVyZaELEwlwYXJ0eU5hbWWCCCouZ292LnVzggZnb3YudXOBDGFkbWluQGdvdi51c4YTaHR0cHM6Ly9nb3YudXMvaG9tZYcEwMAAAQ=="

func TestParseGeneralNamesAll(t *testing.T) {
	// TODO: This should test we can parse a GeneralName that contains all
	// possible types of GeneralName, not that we can parse a DN correctly. We
	// should not rely on implementation details of pkix.Name to handle parsing a
	// GeneralName. More broadly, we should consider refactoring how GeneralName
	// is handled, and maybe move it to the pkix package.
}

func TestTimeInValidityPeriod(t *testing.T) {
	fileBytes, _ := ioutil.ReadFile("testdata/davidadrian.org.cert")
	p, _ := pem.Decode(fileBytes)
	c, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("unable to parse PEM: %s", err)
	}
	tests := []struct {
		unixTime int64
		expected bool
	}{
		{
			unixTime: 946684800, // 2000-01-01 00:00:00
			expected: false,
		},
		{
			unixTime: 0,
			expected: false,
		},
		{
			unixTime: 2208988800, // 2040-01-01 00:00:00
			expected: false,
		},
		{
			unixTime: 1420070400, // 2015-01-01 00:00:00
			expected: true,
		},
	}
	for idx, test := range tests {
		timestamp := time.Unix(test.unixTime, 0)
		if actual := c.TimeInValidityPeriod(timestamp); actual != test.expected {
			t.Errorf("#%d: for time %d got %t, expected %v", idx, test.unixTime, actual, test.expected)
		}
	}
}

func TestParseSignedCertificateTimestampListErrors(t *testing.T) {
	incompleteList, _ := asn1.Marshal([]byte{0x00})
	nodataList, _ := asn1.Marshal([]byte{0x00, 0x00})
	trailingDataList, _ := asn1.Marshal([]byte{0x00, 0x00, 0x00})
	incompleteSCTList, _ := asn1.Marshal([]byte{0x00, 0x00, 0x00, 0x99})
	badSCTList, _ := asn1.Marshal([]byte{0x00, 0x00, 0x00, 0x00, 0x00})

	testCases := []struct {
		name           string
		ext            pkix.Extension
		expectedErrMsg string
	}{
		{
			name:           "incomplete len",
			ext:            pkix.Extension{Value: incompleteList},
			expectedErrMsg: "malformed SCT extension: incomplete length field",
		},
		{
			name:           "trailing data",
			ext:            pkix.Extension{Value: trailingDataList},
			expectedErrMsg: "malformed SCT extension: trailing data",
		},
		{
			name:           "incomplete SCT in list",
			ext:            pkix.Extension{Value: incompleteSCTList},
			expectedErrMsg: "malformed SCT extension: incomplete SCT",
		},
		{
			name:           "bad SCT in list",
			ext:            pkix.Extension{Value: badSCTList},
			expectedErrMsg: "malformed SCT extension: SCT parse err: EOF",
		},
		{
			name: "no data",
			ext:  pkix.Extension{Value: nodataList},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := &Certificate{}
			err := parseSignedCertificateTimestampList(out, tc.ext)

			if err != nil && err.Error() != tc.expectedErrMsg {
				t.Errorf("expected err %q got %q", tc.expectedErrMsg, err.Error())
			} else if err == nil && tc.expectedErrMsg != "" {
				t.Errorf("expected err %q got nil", tc.expectedErrMsg)
			}
		})
	}
}

func TestParseCert(t *testing.T) {
	tcases := []string{
		"testdata/parsecert1.pem",
		"testdata/parsecert2.pem",
		"testdata/parsecert3.pem",
		"testdata/parsecert4-time.pem",
		"testdata/parsecert5-printable.pem",
		"testdata/parsecert6-explicittag.pem",
		"testdata/parsecert7-tagmatch.pem",
		"testdata/parsecert8-rsapositive.pem",
		"testdata/parsecert9-intminlen.pem",
		"testdata/parsecert10-tag.pem",
		"testdata/parsecert11-ia5.pem",
		"testdata/parsecert12-minlen.pem",
	}

	for _, tc := range tcases {
		t.Run(tc, func(t *testing.T) {
			b, err := ioutil.ReadFile(tc)
			require.NoError(t, err)

			block, _ := pem.Decode(b)
			require.NotNil(t, block)

			_, err = ParseCertificate(block.Bytes)
			assert.Error(t, err)
		})
	}

	asn1.AllowPermissiveParsing = true

	for _, tc := range tcases {
		t.Run(tc, func(t *testing.T) {
			b, err := ioutil.ReadFile(tc)
			require.NoError(t, err)

			block, _ := pem.Decode(b)
			require.NotNil(t, block)

			_, err = ParseCertificate(block.Bytes)
			assert.NoError(t, err)
		})
	}
}
