/*
 * ZCrypto Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package certificates

// HexSPKISubjectFingerprintUNIWUCAG01 is the hex of the SPKI Subject Fingerprint for the niversitaet
// Wuerzburg CA G01.
const HexSPKISubjectFingerprintUNIWUCAG01 = "815350018d31c56513467a4f6e2ab242a8ed10000d7cd36827f4ad54ce6ffb7a"

// HexSPKISubjectFingerprintSBHome6Wuerzburg is the hex of the SPKI Subject
// Fingerprint for www-sbhome6.zv.uni-wuerzburg.de.
const HexSPKISubjectFingerprintSBHome6Wuerzburg = "476793e425b89c1df0ab9e0bb4535e53b7132febb8f97476dff74edf982d2b91"

// PEMDAdrianIOSignedByLEX3 is a PEM of a leaf certificate for dadrian.io signed
// by Let's Encrypt Authority X3.
const PEMDAdrianIOSignedByLEX3 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:8c:86:7c:86:51:8d:07:93:4d:e6:06:fa:9b:bb:df:d9:12
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
        Validity
            Not Before: Jun 12 19:31:00 2017 GMT
            Not After : Sep 10 19:31:00 2017 GMT
        Subject: CN=dadrian.io
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f2:a2:65:2f:6c:f9:3b:b4:b2:11:33:15:2e:95:
                    99:b2:2f:d1:3a:df:d0:03:0e:58:a3:29:14:fc:b0:
                    94:4f:53:be:69:e4:2c:b1:b8:d2:3c:b3:31:90:6e:
                    dd:d4:60:f8:c0:84:4f:f6:cb:17:34:87:91:cc:04:
                    4a:04:5b:63:ce:79:fe:a4:19:9c:30:28:11:2f:db:
                    cd:db:cc:d9:0e:72:e1:75:b2:b4:98:06:59:88:ef:
                    9c:9a:df:db:f2:28:ee:fa:26:9c:65:d6:42:00:ed:
                    01:e0:1a:e6:3f:f1:a8:4b:b5:3f:06:b4:c3:e7:60:
                    13:47:fb:8b:a8:28:ec:11:0c:fa:51:db:bc:d8:ec:
                    47:19:96:e1:53:3c:b3:69:7f:6a:29:f1:db:e4:c1:
                    98:f0:c0:f0:bd:78:d4:12:8f:f7:07:d0:58:f3:a8:
                    b3:ea:16:6a:44:cc:18:24:99:f5:73:2d:ab:6f:71:
                    51:d5:d8:d4:34:40:7a:5b:f9:d4:cb:d6:d7:fc:52:
                    61:29:28:1d:de:5c:40:83:69:d8:4c:08:78:bb:65:
                    98:43:5c:f0:24:1a:c1:54:6e:6a:b1:7c:18:7c:3f:
                    e9:ec:6c:41:7a:78:79:b9:28:f6:9d:e7:ee:35:2b:
                    6e:e7:db:b6:56:04:88:d7:99:d5:91:c9:4c:69:67:
                    32:65
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                84:37:E8:FB:ED:4C:19:B3:D4:91:42:E1:F4:3F:69:82:97:D7:27:80
            X509v3 Authority Key Identifier:
                keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1

            Authority Information Access:
                OCSP - URI:http://ocsp.int-x3.letsencrypt.org
                CA Issuers - URI:http://cert.int-x3.letsencrypt.org/

            X509v3 Subject Alternative Name:
                DNS:dadrian.io
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.letsencrypt.org
                  User Notice:
                    Explicit Text: This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/

    Signature Algorithm: sha256WithRSAEncryption
        59:d0:2f:62:cf:bb:a5:7b:bd:32:1e:12:3b:1d:1a:84:e9:82:
        b6:f1:7a:df:7a:8b:d0:6b:da:8a:ca:ff:37:04:3a:f9:2d:76:
        8f:8f:18:77:f3:ef:fe:ad:04:32:64:8c:cb:e1:d1:49:a8:17:
        f0:6b:61:26:3e:59:d3:e7:14:59:4d:ee:55:51:51:00:83:aa:
        9f:ca:c4:16:f4:99:f2:40:81:a5:12:b3:42:b0:f7:ed:c2:1b:
        3f:d6:0b:81:8d:42:05:61:9b:ff:f6:d9:4b:a7:1a:9f:e3:cc:
        f8:c1:4e:a6:dd:1e:ec:6b:72:55:ee:aa:9d:d5:5b:02:7e:d1:
        8c:e7:a5:15:b1:86:d4:82:a1:b7:1b:6a:8e:03:54:6a:c1:7b:
        d9:b2:8d:1c:2d:06:0e:18:b6:94:af:4e:56:bb:b3:1d:3e:b0:
        f8:19:6b:b4:22:81:3c:1c:1b:fb:04:35:6e:e0:4e:0d:48:52:
        3b:bf:bc:d8:35:3c:a6:86:61:c5:17:5d:57:f8:7f:8a:9e:36:
        ed:f4:e9:42:20:36:83:fa:3e:69:a1:ba:3a:d9:20:86:d5:f4:
        3b:68:ef:33:c0:d6:63:02:28:cf:3d:6c:01:cf:43:7f:9f:74:
        c4:4a:d9:23:15:73:cf:b8:80:de:c3:02:c0:ab:e5:3c:38:40:
        67:9a:c6:1d
-----BEGIN CERTIFICATE-----
MIIE9zCCA9+gAwIBAgISA4yGfIZRjQeTTeYG+pu739kSMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA2MTIxOTMxMDBaFw0x
NzA5MTAxOTMxMDBaMBUxEzARBgNVBAMTCmRhZHJpYW4uaW8wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDyomUvbPk7tLIRMxUulZmyL9E639ADDlijKRT8
sJRPU75p5CyxuNI8szGQbt3UYPjAhE/2yxc0h5HMBEoEW2POef6kGZwwKBEv283b
zNkOcuF1srSYBlmI75ya39vyKO76Jpxl1kIA7QHgGuY/8ahLtT8GtMPnYBNH+4uo
KOwRDPpR27zY7EcZluFTPLNpf2op8dvkwZjwwPC9eNQSj/cH0FjzqLPqFmpEzBgk
mfVzLatvcVHV2NQ0QHpb+dTL1tf8UmEpKB3eXECDadhMCHi7ZZhDXPAkGsFUbmqx
fBh8P+nsbEF6eHm5KPad5+41K27n27ZWBIjXmdWRyUxpZzJlAgMBAAGjggIKMIIC
BjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIQ36PvtTBmz1JFC4fQ/aYKX1yeAMB8G
A1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAu
BggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAv
BggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8w
FQYDVR0RBA4wDIIKZGFkcmlhbi5pbzCB/gYDVR0gBIH2MIHzMAgGBmeBDAECATCB
5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2Vu
Y3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMgQ2VydGlmaWNhdGUgbWF5
IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFuZCBvbmx5
IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5k
IGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkvMA0GCSqGSIb3
DQEBCwUAA4IBAQBZ0C9iz7ule70yHhI7HRqE6YK28XrfeovQa9qKyv83BDr5LXaP
jxh38+/+rQQyZIzL4dFJqBfwa2EmPlnT5xRZTe5VUVEAg6qfysQW9JnyQIGlErNC
sPftwhs/1guBjUIFYZv/9tlLpxqf48z4wU6m3R7sa3JV7qqd1VsCftGM56UVsYbU
gqG3G2qOA1RqwXvZso0cLQYOGLaUr05Wu7MdPrD4GWu0IoE8HBv7BDVu4E4NSFI7
v7zYNTymhmHFF11X+H+Knjbt9OlCIDaD+j5pobo62SCG1fQ7aO8zwNZjAijPPWwB
z0N/n3TEStkjFXPPuIDewwLAq+U8OEBnmsYd
-----END CERTIFICATE-----
`

// HexSPKISubjectFingerprintDAdrianIO is the hex of the SPKI Subject Fingerprint
// of the certificate in DAdrianIOSignedByLEX3.
const HexSPKISubjectFingerprintDAdrianIO = "8a5d4cbab48316c11c5b2fa053ad119f807bf41a29cc97f713edd3e46c3f53a2"

// PEMUNIWUCAG01SignedByDFNVerin is the certificate for the Universitaet
// Wuerzburg CA G01 signed by DFN Verein.
const PEMUNIWUCAG01SignedByDFNVerin = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 168689512 (0xa0dff68)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=DE, O=DFN-Verein, OU=DFN-PKI, CN=DFN-Verein PCA Global - G01
        Validity
            Not Before: Mar  7 09:11:54 2007 GMT
            Not After : Mar  6 00:00:00 2019 GMT
        Subject: C=DE, O=Universitaet Wuerzburg, CN=UNIWUE-CA - G01/emailAddress=ca@uni-wuerzburg.de
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:b8:63:35:6b:24:0d:7c:ac:ff:53:f8:3d:7f:e9:
                    76:c1:00:ef:70:aa:b0:71:ec:08:2e:c2:39:44:a6:
                    30:26:ed:53:29:34:0c:c5:5a:ed:d4:2f:95:a2:f5:
                    5a:93:f3:f4:c8:fb:bb:09:fd:92:2b:b2:c9:84:68:
                    b9:45:70:96:42:38:30:cd:75:58:fc:e3:f9:e9:8d:
                    af:ae:c3:1a:f2:b0:74:28:ae:35:39:6e:7b:f8:ca:
                    c0:18:22:84:9f:d6:ac:36:75:d7:d7:26:77:73:ea:
                    a5:81:df:ae:11:25:7b:2f:7d:89:3b:ad:0d:e3:cc:
                    bf:e5:88:0c:ed:2c:39:03:ec:3f:8c:31:c2:5a:4c:
                    26:e2:c2:63:25:1f:96:37:f3:d4:33:27:4e:f5:0f:
                    8d:0c:ee:ab:64:74:a3:b0:5d:96:2e:d6:c5:d6:48:
                    28:ba:2f:1a:c7:8d:94:99:36:f7:7e:d8:6e:d4:b0:
                    d1:a4:37:58:9a:98:71:f4:73:21:72:7b:e9:16:5f:
                    7a:86:52:db:44:8e:23:83:b4:9a:77:42:5a:8c:b1:
                    e8:b2:64:00:86:8d:f6:7a:88:1c:3b:e2:86:14:53:
                    85:9e:70:e5:9b:d7:04:37:d0:34:ac:f7:89:0c:a4:
                    7f:d3:2e:7b:c8:8a:4e:99:9f:be:d9:72:b0:a2:85:
                    92:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage:
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                7D:1F:A8:40:F6:A6:F6:32:4E:81:E5:F8:32:0B:C3:6D:2B:C4:33:6E
            X509v3 Authority Key Identifier:
                keyid:49:B7:C6:CF:E8:3D:1F:7F:EA:44:7B:13:29:F7:F1:0A:70:3E:DE:64

            X509v3 Subject Alternative Name:
                email:ca@uni-wuerzburg.de
            X509v3 CRL Distribution Points:
                URI:http://cdp1.pca.dfn.de/global-root-ca/pub/crl/cacrl.crl
                URI:http://cdp2.pca.dfn.de/global-root-ca/pub/crl/cacrl.crl

            Authority Information Access:
                CA Issuers - URI:http://cdp1.pca.dfn.de/global-root-ca/pub/cacert/cacert.crt
                CA Issuers - URI:http://cdp2.pca.dfn.de/global-root-ca/pub/cacert/cacert.crt

    Signature Algorithm: sha1WithRSAEncryption
        d7:de:af:09:80:1a:82:e1:b6:71:96:a4:4b:56:70:71:d0:ce:
        99:a2:6f:38:cc:7b:99:5e:32:de:e8:5d:d5:03:26:ec:89:8b:
        8b:69:a9:e5:4c:78:c3:a3:1a:7a:40:93:b3:e6:ce:11:38:02:
        1d:b9:4d:21:35:c4:f0:d0:3c:b1:19:14:60:c2:55:c9:6f:cf:
        ed:21:3d:66:4f:94:9b:ad:4a:22:b0:45:55:65:17:f9:7c:e9:
        f0:db:a6:52:c7:97:98:c9:9c:be:ee:8b:ce:41:d5:68:19:43:
        7e:d3:1a:eb:4b:86:99:2f:f6:73:61:6c:6a:88:d7:f3:5f:f5:
        20:b2:ef:69:77:86:de:31:ff:8e:44:ca:5e:67:00:55:bd:4a:
        45:8e:2f:51:95:1b:9a:48:94:c5:da:26:02:2d:48:c2:13:d9:
        6e:38:e8:cc:2d:01:b6:d4:4d:fa:9a:09:77:dd:b0:02:27:fa:
        6d:34:91:1d:9a:4c:c1:6c:92:36:c0:0a:7e:6d:b7:1c:2d:05:
        7f:20:65:57:b5:27:2d:9e:c2:6f:5c:8b:95:35:6b:e3:df:26:
        ac:43:ad:be:49:8c:00:3c:83:bc:4f:f9:1d:1a:3e:3a:b8:a1:
        b5:e3:cb:b1:c0:48:07:ef:27:de:a6:a4:f3:1b:99:f7:30:5a:
        7f:b3:e2:f5
-----BEGIN CERTIFICATE-----
MIIE+DCCA+CgAwIBAgIECg3/aDANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJE
RTETMBEGA1UEChMKREZOLVZlcmVpbjEQMA4GA1UECxMHREZOLVBLSTEkMCIGA1UE
AxMbREZOLVZlcmVpbiBQQ0EgR2xvYmFsIC0gRzAxMB4XDTA3MDMwNzA5MTE1NFoX
DTE5MDMwNjAwMDAwMFowbDELMAkGA1UEBhMCREUxHzAdBgNVBAoTFlVuaXZlcnNp
dGFldCBXdWVyemJ1cmcxGDAWBgNVBAMTD1VOSVdVRS1DQSAtIEcwMTEiMCAGCSqG
SIb3DQEJARYTY2FAdW5pLXd1ZXJ6YnVyZy5kZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALhjNWskDXys/1P4PX/pdsEA73CqsHHsCC7COUSmMCbtUyk0
DMVa7dQvlaL1WpPz9Mj7uwn9kiuyyYRouUVwlkI4MM11WPzj+emNr67DGvKwdCiu
NTlue/jKwBgihJ/WrDZ119cmd3PqpYHfrhEley99iTutDePMv+WIDO0sOQPsP4wx
wlpMJuLCYyUfljfz1DMnTvUPjQzuq2R0o7Bdli7WxdZIKLovGseNlJk2937YbtSw
0aQ3WJqYcfRzIXJ76RZfeoZS20SOI4O0mndCWoyx6LJkAIaN9nqIHDvihhRThZ5w
5ZvXBDfQNKz3iQykf9Mue8iKTpmfvtlysKKFkpMCAwEAAaOCAbIwggGuMA8GA1Ud
EwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBR9H6hA9qb2Mk6B5fgy
C8NtK8QzbjAfBgNVHSMEGDAWgBRJt8bP6D0ff+pEexMp9/EKcD7eZDAeBgNVHREE
FzAVgRNjYUB1bmktd3VlcnpidXJnLmRlMIGIBgNVHR8EgYAwfjA9oDugOYY3aHR0
cDovL2NkcDEucGNhLmRmbi5kZS9nbG9iYWwtcm9vdC1jYS9wdWIvY3JsL2NhY3Js
LmNybDA9oDugOYY3aHR0cDovL2NkcDIucGNhLmRmbi5kZS9nbG9iYWwtcm9vdC1j
YS9wdWIvY3JsL2NhY3JsLmNybDCBogYIKwYBBQUHAQEEgZUwgZIwRwYIKwYBBQUH
MAKGO2h0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvZ2xvYmFsLXJvb3QtY2EvcHViL2Nh
Y2VydC9jYWNlcnQuY3J0MEcGCCsGAQUFBzAChjtodHRwOi8vY2RwMi5wY2EuZGZu
LmRlL2dsb2JhbC1yb290LWNhL3B1Yi9jYWNlcnQvY2FjZXJ0LmNydDANBgkqhkiG
9w0BAQUFAAOCAQEA196vCYAaguG2cZakS1ZwcdDOmaJvOMx7mV4y3uhd1QMm7ImL
i2mp5Ux4w6MaekCTs+bOETgCHblNITXE8NA8sRkUYMJVyW/P7SE9Zk+Um61KIrBF
VWUX+Xzp8NumUseXmMmcvu6LzkHVaBlDftMa60uGmS/2c2FsaojX81/1ILLvaXeG
3jH/jkTKXmcAVb1KRY4vUZUbmkiUxdomAi1IwhPZbjjozC0BttRN+poJd92wAif6
bTSRHZpMwWySNsAKfm23HC0FfyBlV7UnLZ7Cb1yLlTVr498mrEOtvkmMADyDvE/5
HRo+OrihtePLscBIB+8n3qak8xuZ9zBaf7Pi9Q==
-----END CERTIFICATE-----
`

// HexHashPEMUNIWUCAG01SignedByDFNVerin is the hex SHA256 fingerprint of
// UNIWUCAG01SignedByDFNVerin.
const HexHashPEMUNIWUCAG01SignedByDFNVerin = "e06c3af4ea837d9e6346ecfff832bf7b6fcbfc5a5ef3cd37b04496f87b9bedf8"

// PEMSBHome6WuerzburgSignedByUNIWUCAG01 is the certificate for
// www-sbhome6.zv.uni-wuerzburg.de signed by Universitaet Wuerzburg CA G01.
const PEMSBHome6WuerzburgSignedByUNIWUCAG01 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 171129086 (0xa3338fe)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=DE, O=Universitaet Wuerzburg, CN=UNIWUE-CA - G01/emailAddress=ca@uni-wuerzburg.de
        Validity
            Not Before: Apr  4 14:51:28 2007 GMT
            Not After : Apr  2 14:51:28 2012 GMT
        Subject: C=DE, O=Universitaet Wuerzburg, OU=Zentralverwaltung, CN=www-sbhome6.zv.uni-wuerzburg.de
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:cc:96:f9:d3:ef:80:ba:c8:34:f6:37:14:ed:bc:
                    ac:fa:6c:43:f5:1e:fb:29:10:4d:78:9f:16:6e:b5:
                    54:2d:a1:bc:19:6a:bb:27:0e:f4:6a:e2:f4:bb:56:
                    80:2b:6b:7b:2f:22:84:11:e7:fc:43:e8:1b:0c:1f:
                    8f:68:1a:09:1b:42:8c:38:0c:05:78:93:f3:0b:63:
                    a9:27:35:0b:ab:5a:41:e5:b6:9b:2b:35:a1:05:9c:
                    b6:c7:dc:80:03:7d:ac:9d:be:9d:ab:09:88:f7:18:
                    1a:ec:28:d8:1f:af:35:28:6e:c1:21:f6:a0:2c:21:
                    d0:1b:ea:c0:8f:00:29:f2:4a:8e:4d:14:7e:c1:06:
                    9c:30:b3:4a:c0:ef:b4:fd:a5:ec:ad:9d:cb:af:8b:
                    49:6f:c1:b6:44:f8:a6:89:0b:9b:33:ff:9b:93:1a:
                    a6:ca:aa:30:7c:ec:b2:ab:42:a8:8e:10:5f:5e:4b:
                    4a:b1:f6:ee:db:87:59:56:4a:c6:cf:15:7f:87:8f:
                    7e:7d:2d:a5:29:b3:bc:8e:33:2e:1b:14:49:cd:f0:
                    9b:ef:ec:ca:1f:66:f9:cf:29:83:c9:4c:ad:40:8a:
                    23:55:51:07:a9:3d:0b:a8:dd:0c:dd:55:0a:b3:cb:
                    d7:1a:a8:71:29:7b:95:eb:39:c9:58:92:d8:ee:92:
                    a8:f1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Key Identifier:
                68:C3:EC:FC:67:CD:08:0B:06:A3:B7:21:C6:0D:FB:06:D3:88:D6:0E
            X509v3 Authority Key Identifier:
                keyid:7D:1F:A8:40:F6:A6:F6:32:4E:81:E5:F8:32:0B:C3:6D:2B:C4:33:6E

            X509v3 Subject Alternative Name:
                email:infoman@zv.uni-wuerzburg.de
            X509v3 CRL Distribution Points:
                URI:http://cdp1.pca.dfn.de/uniwue-ca/pub/crl/cacrl.crl
                URI:http://cdp2.pca.dfn.de/uniwue-ca/pub/crl/cacrl.crl

            Authority Information Access:
                CA Issuers - URI:http://cdp1.pca.dfn.de/uniwue-ca/pub/cacert/cacert.crt
                CA Issuers - URI:http://cdp2.pca.dfn.de/uniwue-ca/pub/cacert/cacert.crt

    Signature Algorithm: sha1WithRSAEncryption
        8d:b8:b4:24:e6:83:74:1c:e9:6b:ad:09:75:9f:29:80:05:8a:
        9a:00:70:b3:06:6c:70:1e:85:17:c0:72:1e:7c:77:32:f4:41:
        33:b4:d6:1f:c9:21:3e:19:1b:e9:03:11:c1:b2:28:ef:03:b8:
        88:a7:8c:45:29:79:ff:47:b3:79:50:ab:b0:0e:19:25:d6:2d:
        57:1b:6c:d2:aa:48:72:d1:cc:4e:89:ac:d2:64:07:ca:a7:16:
        1f:4d:4c:11:d4:5c:f4:2e:97:1e:7b:06:3d:32:b7:0e:c1:af:
        26:df:47:23:bd:77:47:df:be:67:4c:8c:95:fd:de:97:ef:fd:
        71:5a:cd:a6:5d:d7:cb:d6:5d:7b:40:90:ee:87:7e:96:59:29:
        19:31:7f:47:d5:ce:4b:36:82:8a:6e:06:cd:9e:d3:9b:97:7b:
        78:6e:a9:d9:8a:5d:6a:41:77:07:28:c9:2f:ab:0e:a7:2c:6f:
        59:c2:9b:cc:52:eb:44:fd:38:1f:7d:31:05:55:b8:1e:3a:63:
        a9:36:37:bb:88:55:4e:0d:46:81:7d:00:26:26:2d:1f:be:cf:
        9c:7f:5f:04:98:6d:45:bb:84:76:39:2c:d9:be:a1:71:44:ba:
        36:c2:b2:b7:12:e8:af:01:df:72:e5:fa:da:3c:71:13:fd:9c:
        2a:85:0e:f6
-----BEGIN CERTIFICATE-----
MIIFEzCCA/ugAwIBAgIECjM4/jANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJE
RTEfMB0GA1UEChMWVW5pdmVyc2l0YWV0IFd1ZXJ6YnVyZzEYMBYGA1UEAxMPVU5J
V1VFLUNBIC0gRzAxMSIwIAYJKoZIhvcNAQkBFhNjYUB1bmktd3VlcnpidXJnLmRl
MB4XDTA3MDQwNDE0NTEyOFoXDTEyMDQwMjE0NTEyOFowdDELMAkGA1UEBhMCREUx
HzAdBgNVBAoTFlVuaXZlcnNpdGFldCBXdWVyemJ1cmcxGjAYBgNVBAsTEVplbnRy
YWx2ZXJ3YWx0dW5nMSgwJgYDVQQDEx93d3ctc2Job21lNi56di51bmktd3Vlcnpi
dXJnLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJb50++Ausg0
9jcU7bys+mxD9R77KRBNeJ8WbrVULaG8GWq7Jw70auL0u1aAK2t7LyKEEef8Q+gb
DB+PaBoJG0KMOAwFeJPzC2OpJzULq1pB5babKzWhBZy2x9yAA32snb6dqwmI9xga
7CjYH681KG7BIfagLCHQG+rAjwAp8kqOTRR+wQacMLNKwO+0/aXsrZ3Lr4tJb8G2
RPimiQubM/+bkxqmyqowfOyyq0KojhBfXktKsfbu24dZVkrGzxV/h49+fS2lKbO8
jjMuGxRJzfCb7+zKH2b5zymDyUytQIojVVEHqT0LqN0M3VUKs8vXGqhxKXuV6znJ
WJLY7pKo8QIDAQABo4IBszCCAa8wCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFGjD7PxnzQgLBqO3IcYN+wbTiNYO
MB8GA1UdIwQYMBaAFH0fqED2pvYyToHl+DILw20rxDNuMCYGA1UdEQQfMB2BG2lu
Zm9tYW5AenYudW5pLXd1ZXJ6YnVyZy5kZTB9BgNVHR8EdjB0MDigNqA0hjJodHRw
Oi8vY2RwMS5wY2EuZGZuLmRlL3VuaXd1ZS1jYS9wdWIvY3JsL2NhY3JsLmNybDA4
oDagNIYyaHR0cDovL2NkcDIucGNhLmRmbi5kZS91bml3dWUtY2EvcHViL2NybC9j
YWNybC5jcmwwgZgGCCsGAQUFBwEBBIGLMIGIMEIGCCsGAQUFBzAChjZodHRwOi8v
Y2RwMS5wY2EuZGZuLmRlL3VuaXd1ZS1jYS9wdWIvY2FjZXJ0L2NhY2VydC5jcnQw
QgYIKwYBBQUHMAKGNmh0dHA6Ly9jZHAyLnBjYS5kZm4uZGUvdW5pd3VlLWNhL3B1
Yi9jYWNlcnQvY2FjZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAQEAjbi0JOaDdBzp
a60JdZ8pgAWKmgBwswZscB6FF8ByHnx3MvRBM7TWH8khPhkb6QMRwbIo7wO4iKeM
RSl5/0ezeVCrsA4ZJdYtVxts0qpIctHMToms0mQHyqcWH01MEdRc9C6XHnsGPTK3
DsGvJt9HI713R9++Z0yMlf3el+/9cVrNpl3Xy9Zde0CQ7od+llkpGTF/R9XOSzaC
im4GzZ7Tm5d7eG6p2YpdakF3ByjJL6sOpyxvWcKbzFLrRP04H30xBVW4HjpjqTY3
u4hVTg1GgX0AJiYtH77PnH9fBJhtRbuEdjks2b6hcUS6NsKytxLorwHfcuX62jxx
E/2cKoUO9g==
-----END CERTIFICATE-----
`

// HexHashPEMSBHome6WuerzburgSignedByUNIWUCAG01 is the hex SHA256 fingerprint of SBHome6WuerzburgSignedByUNIWUCAG01.
const HexHashPEMSBHome6WuerzburgSignedByUNIWUCAG01 = "956ba7bcb13113915f2501501bf7ea5104c9969ac301475385130f8f5e4df56b"
