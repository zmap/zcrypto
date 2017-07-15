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
// of the certificate in PEMDAdrianIOSignedByLEX3.
const HexSPKISubjectFingerprintDAdrianIO = "8a5d4cbab48316c11c5b2fa053ad119f807bf41a29cc97f713edd3e46c3f53a2"
