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

// HexSPKISubjectFingerprintDoDRootCA3 is the hex of the SPKI Subject
// Fingerprint for the DoD Root CA 3.
const HexSPKISubjectFingerprintDoDRootCA3 = "e90ccfd162ae66b7d6e9771abf6c461837c813a5589f693b65c66c3803cf8f4c"

// HexSPKISubjectFingerprintDoDInteropCA2 is the hex of the SPKI Subject
// Fingerprint for the DoD Interoperability CA 2.
const HexSPKISubjectFingerprintDoDInteropCA2 = "a55a05216a8f75908ceec798c466e892cd5b505767d057b2204daa111de0c809"

// PEMDoDRootCA3SelfSigned is the "DoD Root CA 3" self-signed certificate.
const PEMDoDRootCA3SelfSigned string = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA 3
        Validity
            Not Before: Mar 20 18:46:41 2012 GMT
            Not After : Dec 30 18:46:41 2029 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA 3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:a9:ec:14:72:8a:e8:4b:70:a3:da:10:03:84:a6:
                    fb:a7:36:0d:2a:3a:52:16:bf:30:15:52:86:05:47:
                    20:cf:aa:a6:cd:75:c4:64:6e:ef:f1:60:23:cb:0a:
                    66:40:ae:b4:c8:68:2a:00:51:68:49:37:e9:59:32:
                    4d:95:bc:43:27:e9:40:8d:3a:10:ce:14:bc:43:18:
                    a1:f9:de:cc:e7:85:76:73:5e:18:1a:23:5b:bd:3f:
                    1f:f2:ed:8d:19:cc:03:d1:40:a4:8f:a7:20:02:4c:
                    27:5a:79:36:f6:a3:37:21:8e:00:5a:06:16:ca:d3:
                    55:96:6f:31:29:bb:72:0e:cb:e2:48:51:f2:d4:37:
                    a4:35:d6:6f:ee:17:b3:b1:06:ab:0b:19:86:e8:23:
                    6d:31:1b:28:78:65:c5:de:62:52:bc:c1:7d:eb:ee:
                    a0:5d:54:04:fb:b2:cb:2b:b2:23:54:91:82:4c:f0:
                    bf:ba:74:40:3b:0c:04:45:80:67:5c:c5:eb:a2:57:
                    c3:1a:7f:0a:2d:bd:7f:b9:dc:c1:99:b0:c8:07:e4:
                    0c:86:36:94:3a:25:2f:f2:7d:e6:97:3c:1b:94:b4:
                    97:59:06:c9:3a:e4:0b:d9:ea:e9:fc:3b:73:34:6f:
                    fd:e7:98:e4:f3:a1:c2:90:5f:1c:f5:3f:2e:d7:19:
                    d3:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                6C:8A:94:A2:77:B1:80:72:1D:81:7A:16:AA:F2:DC:CE:66:EE:45:C0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
        9f:71:a4:c0:b6:96:d2:80:43:a0:48:e9:1f:76:04:f9:c5:3c:
        ad:66:18:58:63:9b:c3:b6:e8:68:8a:85:5a:42:66:12:b4:d2:
        e6:8b:88:7f:87:f4:98:f5:a8:c6:09:c9:1f:f0:2c:1f:ec:82:
        b8:f4:a5:47:38:c1:33:2b:df:4c:7e:9a:be:0b:0b:b1:cb:0f:
        7c:50:28:10:cf:8a:8d:a2:e9:ba:ac:86:d7:d4:b1:93:5f:22:
        8f:96:05:b4:4e:0c:75:91:7d:d3:f2:e7:94:c2:94:14:76:4f:
        8f:0c:ab:10:87:58:32:85:07:75:86:12:0b:5e:ea:53:b4:0a:
        c8:4c:84:92:1f:eb:e8:41:86:3c:ba:f4:4e:41:4a:d1:6c:58:
        47:41:c3:86:5a:f2:ee:e9:f2:98:27:82:ea:2e:36:d6:f8:06:
        5e:82:f1:a0:52:93:44:09:ba:d2:a9:19:5a:58:a3:a8:5d:20:
        6d:4f:64:f8:30:87:1b:90:13:48:81:cd:ca:90:c7:0d:c1:d4:
        98:3f:8e:f2:0e:57:68:33:12:8e:99:09:b1:f0:e4:f6:10:f4:
        36:f2:49:bd:ea:a3:38:c8:56:41:23:83:9a:df:a1:1b:35:7c:
        eb:3f:41:b3:f5:6f:4b:3a:5e:ae:6f:93:76:98:d2:f1:99:9d:
        45:c4:8e:72
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xMjAzMjAxODQ2NDFaFw0y
OTEyMzAxODQ2NDFaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqewUcoro
S3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXEZG7v8WAjywpmQK60yGgqAFFo
STfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14YGiNbvT8f8u2NGcwD0UCkj6cg
AkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy1DekNdZv7hezsQarCxmG6CNt
MRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/unRAOwwERYBnXMXrolfDGn8K
Lb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJOuQL2erp/DtzNG/955jk86HC
kF8c9T8u1xnTfwIDAQABo0IwQDAdBgNVHQ4EFgQUbIqUonexgHIdgXoWqvLczmbu
RcAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAJ9xpMC2ltKAQ6BI6R92BPnFPK1mGFhjm8O26GiKhVpCZhK00uaLiH+H
9Jj1qMYJyR/wLB/sgrj0pUc4wTMr30x+mr4LC7HLD3xQKBDPio2i6bqshtfUsZNf
Io+WBbRODHWRfdPy55TClBR2T48MqxCHWDKFB3WGEgte6lO0CshMhJIf6+hBhjy6
9E5BStFsWEdBw4Za8u7p8pgnguouNtb4Bl6C8aBSk0QJutKpGVpYo6hdIG1PZPgw
hxuQE0iBzcqQxw3B1Jg/jvIOV2gzEo6ZCbHw5PYQ9DbySb3qozjIVkEjg5rfoRs1
fOs/QbP1b0s6Xq5vk3aY0vGZnUXEjnI=
-----END CERTIFICATE-----
`

// HexHashPEMDoDRootCA3SelfSigned is the hex SHA256 fingerprint of
// PEMDoDRootCA3SelfSigned.
const HexHashPEMDoDRootCA3SelfSigned = "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2"

// PEMDoDRootCA3SignedByDoDInteropCA2Serial655 is the PEM of a certificate for
// the DoD Root CA 3 signed by DoD Interoperability CA 2 with serial number 655.
const PEMDoDRootCA3SignedByDoDInteropCA2Serial655 string = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 655 (0x28f)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Validity
            Not Before: Sep 23 16:37:25 2015 GMT
            Not After : Sep 23 16:37:25 2018 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA 3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:a9:ec:14:72:8a:e8:4b:70:a3:da:10:03:84:a6:
                    fb:a7:36:0d:2a:3a:52:16:bf:30:15:52:86:05:47:
                    20:cf:aa:a6:cd:75:c4:64:6e:ef:f1:60:23:cb:0a:
                    66:40:ae:b4:c8:68:2a:00:51:68:49:37:e9:59:32:
                    4d:95:bc:43:27:e9:40:8d:3a:10:ce:14:bc:43:18:
                    a1:f9:de:cc:e7:85:76:73:5e:18:1a:23:5b:bd:3f:
                    1f:f2:ed:8d:19:cc:03:d1:40:a4:8f:a7:20:02:4c:
                    27:5a:79:36:f6:a3:37:21:8e:00:5a:06:16:ca:d3:
                    55:96:6f:31:29:bb:72:0e:cb:e2:48:51:f2:d4:37:
                    a4:35:d6:6f:ee:17:b3:b1:06:ab:0b:19:86:e8:23:
                    6d:31:1b:28:78:65:c5:de:62:52:bc:c1:7d:eb:ee:
                    a0:5d:54:04:fb:b2:cb:2b:b2:23:54:91:82:4c:f0:
                    bf:ba:74:40:3b:0c:04:45:80:67:5c:c5:eb:a2:57:
                    c3:1a:7f:0a:2d:bd:7f:b9:dc:c1:99:b0:c8:07:e4:
                    0c:86:36:94:3a:25:2f:f2:7d:e6:97:3c:1b:94:b4:
                    97:59:06:c9:3a:e4:0b:d9:ea:e9:fc:3b:73:34:6f:
                    fd:e7:98:e4:f3:a1:c2:90:5f:1c:f5:3f:2e:d7:19:
                    d3:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78

            X509v3 Subject Key Identifier:
                6C:8A:94:A2:77:B1:80:72:1D:81:7A:16:AA:F2:DC:CE:66:EE:45:C0
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c
                OCSP - URI:http://ocsp.disa.mil

            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.39
                Policy: 2.16.840.1.101.2.1.11.42
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODROOTCA3_IB.p7c

    Signature Algorithm: sha256WithRSAEncryption
        8c:30:87:13:a9:7d:fb:98:fc:50:ca:a1:20:8a:9c:10:7b:0c:
        c4:d7:0c:d9:4d:5e:36:26:24:ed:2b:5f:75:ed:9a:0a:b8:e9:
        6e:5f:20:a3:19:ef:39:24:3e:9e:a2:e1:19:c5:b3:53:fc:58:
        e6:8e:ca:84:fa:cd:35:94:38:6d:f2:e3:3e:04:31:dc:7b:ec:
        d5:fc:3a:2e:34:46:1c:e4:50:c1:74:ce:e9:fc:87:89:21:a6:
        a5:27:a2:9f:fb:f0:88:3a:d8:95:a4:d1:b9:78:d0:fd:c3:54:
        1a:b9:8d:9f:df:af:b6:60:96:8c:66:bb:55:92:d9:08:53:94:
        ca:35:f4:e3:87:93:2a:64:e3:ba:69:d1:5c:f3:1d:2e:7b:1c:
        4f:3a:95:c2:f6:b3:bc:e0:40:c8:83:c2:9e:3d:50:02:cf:7b:
        eb:f4:2d:b2:06:98:2d:07:5d:d3:06:2a:de:6e:e1:4d:57:0c:
        81:b6:08:e4:18:98:22:ce:44:94:00:b6:7f:ae:8d:84:57:66:
        40:b5:b6:67:95:67:41:53:4b:8b:e9:3f:e7:28:e9:b2:80:dd:
        7d:d9:7c:89:40:2e:55:e1:45:5f:d5:47:6a:9b:b6:34:03:97:
        5e:32:a5:ec:3e:02:d6:49:a5:c9:4f:85:21:d8:f8:0e:9f:a8:
        2d:6c:02:f0
-----BEGIN CERTIFICATE-----
MIIFHDCCBASgAwIBAgICAo8wDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQL
EwNQS0kxJzAlBgNVBAMTHkRvRCBJbnRlcm9wZXJhYmlsaXR5IFJvb3QgQ0EgMjAe
Fw0xNTA5MjMxNjM3MjVaFw0xODA5MjMxNjM3MjVaMFsxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
UEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAqewUcoroS3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXE
ZG7v8WAjywpmQK60yGgqAFFoSTfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14Y
GiNbvT8f8u2NGcwD0UCkj6cgAkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy
1DekNdZv7hezsQarCxmG6CNtMRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/
unRAOwwERYBnXMXrolfDGn8KLb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJ
OuQL2erp/DtzNG/955jk86HCkF8c9T8u1xnTfwIDAQABo4IB1zCCAdMwHwYDVR0j
BBgwFoAU//iuE4uSK3mSQaN2XCyBnprFnHgwHQYDVR0OBBYEFGyKlKJ3sYByHYF6
Fqry3M5m7kXAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMEcGA1Ud
HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElOVEVST1BF
UkFCSUxJVFlST09UQ0EyLmNybDB8BggrBgEFBQcBAQRwMG4wSgYIKwYBBQUHMAKG
Pmh0dHA6Ly9jcmwuZGlzYS5taWwvaXNzdWVkdG8vRE9ESU5URVJPUEVSQUJJTElU
WVJPT1RDQTJfSVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1p
bDBMBgNVHSAERTBDMAsGCWCGSAFlAgELJDALBglghkgBZQIBCycwCwYJYIZIAWUC
AQsqMAwGCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgEDETAPBgNVHSQBAf8EBTADgAEA
MEoGCCsGAQUFBwELBD4wPDA6BggrBgEFBQcwBYYuaHR0cDovL2NybC5kaXNhLm1p
bC9pc3N1ZWRieS9ET0RST09UQ0EzX0lCLnA3YzANBgkqhkiG9w0BAQsFAAOCAQEA
jDCHE6l9+5j8UMqhIIqcEHsMxNcM2U1eNiYk7Stfde2aCrjpbl8goxnvOSQ+nqLh
GcWzU/xY5o7KhPrNNZQ4bfLjPgQx3Hvs1fw6LjRGHORQwXTO6fyHiSGmpSein/vw
iDrYlaTRuXjQ/cNUGrmNn9+vtmCWjGa7VZLZCFOUyjX044eTKmTjumnRXPMdLnsc
TzqVwvazvOBAyIPCnj1QAs976/QtsgaYLQdd0wYq3m7hTVcMgbYI5BiYIs5ElAC2
f66NhFdmQLW2Z5VnQVNLi+k/5yjpsoDdfdl8iUAuVeFFX9VHapu2NAOXXjKl7D4C
1kmlyU+FIdj4Dp+oLWwC8A==
-----END CERTIFICATE-----
`

// HexHashPEMDoDRootCA3SignedByDoDInteropCA2Serial655 is the hex SHA256
// fingerprint of PEMDoDRootCA3SignedByDoDInteropCA2Serial655.
const HexHashPEMDoDRootCA3SignedByDoDInteropCA2Serial655 = "fc326b6b92fd2a3dd0c2961428672bf10f974552319f6930c62c6c791d18e84a"

// PEMDoDRootCA3SignedByDoDInteropCA2Serial748 is the certificate for the DoD
// Root CA 3 signed by the DoD Interoperability CA 2 with serial number 748.
const PEMDoDRootCA3SignedByDoDInteropCA2Serial748 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 748 (0x2ec)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Validity
            Not Before: Feb 17 14:32:11 2016 GMT
            Not After : Feb 17 14:32:11 2019 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA 3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:a9:ec:14:72:8a:e8:4b:70:a3:da:10:03:84:a6:
                    fb:a7:36:0d:2a:3a:52:16:bf:30:15:52:86:05:47:
                    20:cf:aa:a6:cd:75:c4:64:6e:ef:f1:60:23:cb:0a:
                    66:40:ae:b4:c8:68:2a:00:51:68:49:37:e9:59:32:
                    4d:95:bc:43:27:e9:40:8d:3a:10:ce:14:bc:43:18:
                    a1:f9:de:cc:e7:85:76:73:5e:18:1a:23:5b:bd:3f:
                    1f:f2:ed:8d:19:cc:03:d1:40:a4:8f:a7:20:02:4c:
                    27:5a:79:36:f6:a3:37:21:8e:00:5a:06:16:ca:d3:
                    55:96:6f:31:29:bb:72:0e:cb:e2:48:51:f2:d4:37:
                    a4:35:d6:6f:ee:17:b3:b1:06:ab:0b:19:86:e8:23:
                    6d:31:1b:28:78:65:c5:de:62:52:bc:c1:7d:eb:ee:
                    a0:5d:54:04:fb:b2:cb:2b:b2:23:54:91:82:4c:f0:
                    bf:ba:74:40:3b:0c:04:45:80:67:5c:c5:eb:a2:57:
                    c3:1a:7f:0a:2d:bd:7f:b9:dc:c1:99:b0:c8:07:e4:
                    0c:86:36:94:3a:25:2f:f2:7d:e6:97:3c:1b:94:b4:
                    97:59:06:c9:3a:e4:0b:d9:ea:e9:fc:3b:73:34:6f:
                    fd:e7:98:e4:f3:a1:c2:90:5f:1c:f5:3f:2e:d7:19:
                    d3:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78

            X509v3 Subject Key Identifier:
                6C:8A:94:A2:77:B1:80:72:1D:81:7A:16:AA:F2:DC:CE:66:EE:45:C0
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c
                OCSP - URI:http://ocsp.disa.mil

            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.39
                Policy: 2.16.840.1.101.2.1.11.42
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.39

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODROOTCA3_IB.p7c

    Signature Algorithm: sha256WithRSAEncryption
        77:f6:ef:07:25:8d:e5:85:60:05:6a:39:83:fb:1c:c4:da:6f:
        d7:91:78:0d:16:cb:d9:a6:6d:37:94:1d:c7:44:71:d1:e9:41:
        8f:d2:bb:05:02:52:75:47:0a:10:84:ce:4d:e7:e4:04:5d:42:
        1e:21:39:c5:88:e3:0a:b6:50:05:31:3f:8f:d0:8c:56:75:d4:
        43:3e:fe:df:1c:4d:86:97:70:e7:22:62:3f:40:76:96:66:86:
        41:8f:17:01:29:30:b7:0a:a7:9f:6a:a2:41:be:88:a7:fa:59:
        75:2f:f3:de:e6:a4:f0:f4:2c:60:65:0f:74:c5:65:5c:b4:bd:
        d2:c7:e7:33:d8:74:16:d2:ff:a9:29:c7:8d:d0:c7:23:04:3a:
        e9:eb:1b:6f:9a:59:24:3e:86:5f:e5:9e:0d:ac:c3:2c:6b:c0:
        64:30:01:eb:13:5d:aa:a7:f6:31:9e:88:fd:29:db:ba:e5:54:
        a6:86:c2:1e:8e:34:77:02:ea:1f:6c:cc:f6:0b:83:e6:27:8b:
        b0:4a:88:92:5c:3a:39:10:8b:c9:48:c9:e3:1b:34:1e:41:43:
        6e:95:de:b0:c7:97:f0:a5:e2:93:0c:de:6a:df:72:9d:be:3e:
        ee:4c:62:9c:10:b0:ed:2b:fb:c6:95:f8:4a:24:1e:8e:29:1b:
        dc:93:f5:e4
-----BEGIN CERTIFICATE-----
MIIFKjCCBBKgAwIBAgICAuwwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQL
EwNQS0kxJzAlBgNVBAMTHkRvRCBJbnRlcm9wZXJhYmlsaXR5IFJvb3QgQ0EgMjAe
Fw0xNjAyMTcxNDMyMTFaFw0xOTAyMTcxNDMyMTFaMFsxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
UEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAqewUcoroS3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXE
ZG7v8WAjywpmQK60yGgqAFFoSTfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14Y
GiNbvT8f8u2NGcwD0UCkj6cgAkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy
1DekNdZv7hezsQarCxmG6CNtMRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/
unRAOwwERYBnXMXrolfDGn8KLb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJ
OuQL2erp/DtzNG/955jk86HCkF8c9T8u1xnTfwIDAQABo4IB5TCCAeEwHwYDVR0j
BBgwFoAU//iuE4uSK3mSQaN2XCyBnprFnHgwHQYDVR0OBBYEFGyKlKJ3sYByHYF6
Fqry3M5m7kXAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMEcGA1Ud
HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElOVEVST1BF
UkFCSUxJVFlST09UQ0EyLmNybDB8BggrBgEFBQcBAQRwMG4wSgYIKwYBBQUHMAKG
Pmh0dHA6Ly9jcmwuZGlzYS5taWwvaXNzdWVkdG8vRE9ESU5URVJPUEVSQUJJTElU
WVJPT1RDQTJfSVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1p
bDBaBgNVHSAEUzBRMAsGCWCGSAFlAgELJDALBglghkgBZQIBCycwCwYJYIZIAWUC
AQsqMAwGCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgEDETAMBgpghkgBZQMCAQMnMA8G
A1UdJAEB/wQFMAOAAQAwSgYIKwYBBQUHAQsEPjA8MDoGCCsGAQUFBzAFhi5odHRw
Oi8vY3JsLmRpc2EubWlsL2lzc3VlZGJ5L0RPRFJPT1RDQTNfSUIucDdjMA0GCSqG
SIb3DQEBCwUAA4IBAQB39u8HJY3lhWAFajmD+xzE2m/XkXgNFsvZpm03lB3HRHHR
6UGP0rsFAlJ1RwoQhM5N5+QEXUIeITnFiOMKtlAFMT+P0IxWddRDPv7fHE2Gl3Dn
ImI/QHaWZoZBjxcBKTC3CqefaqJBvoin+ll1L/Pe5qTw9CxgZQ90xWVctL3Sx+cz
2HQW0v+pKceN0McjBDrp6xtvmlkkPoZf5Z4NrMMsa8BkMAHrE12qp/Yxnoj9Kdu6
5VSmhsIejjR3AuofbMz2C4PmJ4uwSoiSXDo5EIvJSMnjGzQeQUNuld6wx5fwpeKT
DN5q33Kdvj7uTGKcELDtK/vGlfhKJB6OKRvck/Xk
-----END CERTIFICATE-----
`

// HexHashPEMDoDRootCA3SignedByDoDInteropCA2Serial748 is the hex SHA256
// fingerprint of PEMDoDRootCA3SignedByDoDInteropCA2Serial748.
const HexHashPEMDoDRootCA3SignedByDoDInteropCA2Serial748 = "42e59ccbf68c413a10dd1bb6bc41a930bf1228e16905d9301559cfc4083d589b"

// PEMDoDRootCA3SignedByCCEBInteropRootCA2 is the certificate for DoD Root CA 3
// signed by the DoD CCEB Interoperability Root CA 2.
const PEMDoDRootCA3SignedByCCEBInteropRootCA2 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 28 (0x1c)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=US DoD CCEB Interoperability Root CA 2
        Validity
            Not Before: Sep 27 12:41:41 2016 GMT
            Not After : Sep 27 12:41:41 2019 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA 3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:a9:ec:14:72:8a:e8:4b:70:a3:da:10:03:84:a6:
                    fb:a7:36:0d:2a:3a:52:16:bf:30:15:52:86:05:47:
                    20:cf:aa:a6:cd:75:c4:64:6e:ef:f1:60:23:cb:0a:
                    66:40:ae:b4:c8:68:2a:00:51:68:49:37:e9:59:32:
                    4d:95:bc:43:27:e9:40:8d:3a:10:ce:14:bc:43:18:
                    a1:f9:de:cc:e7:85:76:73:5e:18:1a:23:5b:bd:3f:
                    1f:f2:ed:8d:19:cc:03:d1:40:a4:8f:a7:20:02:4c:
                    27:5a:79:36:f6:a3:37:21:8e:00:5a:06:16:ca:d3:
                    55:96:6f:31:29:bb:72:0e:cb:e2:48:51:f2:d4:37:
                    a4:35:d6:6f:ee:17:b3:b1:06:ab:0b:19:86:e8:23:
                    6d:31:1b:28:78:65:c5:de:62:52:bc:c1:7d:eb:ee:
                    a0:5d:54:04:fb:b2:cb:2b:b2:23:54:91:82:4c:f0:
                    bf:ba:74:40:3b:0c:04:45:80:67:5c:c5:eb:a2:57:
                    c3:1a:7f:0a:2d:bd:7f:b9:dc:c1:99:b0:c8:07:e4:
                    0c:86:36:94:3a:25:2f:f2:7d:e6:97:3c:1b:94:b4:
                    97:59:06:c9:3a:e4:0b:d9:ea:e9:fc:3b:73:34:6f:
                    fd:e7:98:e4:f3:a1:c2:90:5f:1c:f5:3f:2e:d7:19:
                    d3:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:16:2B:91:DA:E2:17:0C:96:AB:5C:7D:DE:7D:48:F2:5D:A8:00:AC:E7

            X509v3 Subject Key Identifier:
                6C:8A:94:A2:77:B1:80:72:1D:81:7A:16:AA:F2:DC:CE:66:EE:45:C0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.39
                Policy: 2.16.840.1.101.2.1.11.42

            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/USDODCCEBINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/USDODCCEBINTEROPERABILITYROOTCA2_IT.p7c
                OCSP - URI:http://ocsp.disa.mil

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODROOTCA3_IB.p7c

    Signature Algorithm: sha256WithRSAEncryption
        47:e1:98:48:c9:7c:2a:1f:60:aa:17:fc:51:bf:57:e1:46:1d:
        6e:af:2a:47:64:47:d3:f8:23:2c:d0:6f:aa:ae:4c:93:95:b6:
        18:da:f4:1a:b1:97:e9:09:1e:10:b2:12:66:a5:7c:03:15:e5:
        b1:ff:98:7b:c2:11:d3:1f:3c:fa:97:43:cb:bc:83:66:1e:01:
        fd:86:fd:c3:c8:0f:bb:0f:ca:82:72:77:d5:7f:08:7e:ba:b1:
        d3:27:03:3a:d9:94:81:9d:f8:44:17:b1:bf:20:2e:e8:8e:d3:
        67:d6:8d:e6:f6:54:bc:7f:fa:cd:37:3d:f6:e6:f8:dd:b6:01:
        89:b4:a8:b9:7c:a1:40:e4:2b:00:d5:78:be:a1:27:f1:26:48:
        44:e7:f9:11:c4:dc:df:59:7b:86:70:c4:62:0a:44:79:aa:74:
        5f:25:ac:2f:9f:7a:d1:d7:f2:85:86:83:89:e4:20:24:57:9f:
        e7:b5:f0:be:d0:c6:2d:94:ae:f9:01:6a:f3:b6:69:b1:4a:73:
        76:33:a2:72:5a:5a:2a:96:8b:54:3e:f4:de:90:78:61:88:17:
        e5:db:8c:4f:a6:13:f7:10:f8:8d:a5:b4:2d:7f:b2:19:65:7f:
        15:fc:4f:08:8a:0f:06:a5:62:a9:b3:9a:ee:2f:b1:97:31:b2:
        04:c2:e4:47
-----BEGIN CERTIFICATE-----
MIIFFDCCA/ygAwIBAgIBHDANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEvMC0GA1UEAxMmVVMgRG9EIENDRUIgSW50ZXJvcGVyYWJpbGl0eSBSb290
IENBIDIwHhcNMTYwOTI3MTI0MTQxWhcNMTkwOTI3MTI0MTQxWjBbMQswCQYDVQQG
EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAK
BgNVBAsTA1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKnsFHKK6Etwo9oQA4Sm+6c2DSo6Uha/MBVShgVH
IM+qps11xGRu7/FgI8sKZkCutMhoKgBRaEk36VkyTZW8QyfpQI06EM4UvEMYofne
zOeFdnNeGBojW70/H/LtjRnMA9FApI+nIAJMJ1p5NvajNyGOAFoGFsrTVZZvMSm7
cg7L4khR8tQ3pDXWb+4Xs7EGqwsZhugjbTEbKHhlxd5iUrzBfevuoF1UBPuyyyuy
I1SRgkzwv7p0QDsMBEWAZ1zF66JXwxp/Ci29f7ncwZmwyAfkDIY2lDolL/J95pc8
G5S0l1kGyTrkC9nq6fw7czRv/eeY5POhwpBfHPU/LtcZ038CAwEAAaOCAcgwggHE
MB8GA1UdIwQYMBaAFBYrkdriFwyWq1x93n1I8l2oAKznMB0GA1UdDgQWBBRsipSi
d7GAch2Behaq8tzOZu5FwDAOBgNVHQ8BAf8EBAMCAQYwMAYDVR0gBCkwJzALBglg
hkgBZQIBCyQwCwYJYIZIAWUCAQsnMAsGCWCGSAFlAgELKjAPBgNVHRMBAf8EBTAD
AQH/MA8GA1UdJAEB/wQFMAOAAQAwTQYDVR0fBEYwRDBCoECgPoY8aHR0cDovL2Ny
bC5kaXNhLm1pbC9jcmwvVVNET0RDQ0VCSU5URVJPUEVSQUJJTElUWVJPT1RDQTIu
Y3JsMIGCBggrBgEFBQcBAQR2MHQwUAYIKwYBBQUHMAKGRGh0dHA6Ly9jcmwuZGlz
YS5taWwvaXNzdWVkdG8vVVNET0RDQ0VCSU5URVJPUEVSQUJJTElUWVJPT1RDQTJf
SVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1pbDBKBggrBgEF
BQcBCwQ+MDwwOgYIKwYBBQUHMAWGLmh0dHA6Ly9jcmwuZGlzYS5taWwvaXNzdWVk
YnkvRE9EUk9PVENBM19JQi5wN2MwDQYJKoZIhvcNAQELBQADggEBAEfhmEjJfCof
YKoX/FG/V+FGHW6vKkdkR9P4IyzQb6quTJOVthja9Bqxl+kJHhCyEmalfAMV5bH/
mHvCEdMfPPqXQ8u8g2YeAf2G/cPID7sPyoJyd9V/CH66sdMnAzrZlIGd+EQXsb8g
LuiO02fWjeb2VLx/+s03Pfbm+N22AYm0qLl8oUDkKwDVeL6hJ/EmSETn+RHE3N9Z
e4ZwxGIKRHmqdF8lrC+fetHX8oWGg4nkICRXn+e18L7Qxi2UrvkBavO2abFKc3Yz
onJaWiqWi1Q+9N6QeGGIF+XbjE+mE/cQ+I2ltC1/shllfxX8TwiKDwalYqmzmu4v
sZcxsgTC5Ec=
-----END CERTIFICATE-----
`

// HexHashPEMDoDRootCA3SignedByCCEBInteropRootCA2 is the hex SHA256 fingerprint
// of PEMDoDRootCA3SignedByCCEBInteropRootCA2.
const HexHashPEMDoDRootCA3SignedByCCEBInteropRootCA2 = "925820ceae31ca372175d0eda58063e0bf8d7f6bd1a6de007d22861bb6270b62"

// PEMDoDInteropCA2SignedByFederalBridgeCA2016 is a certificate for the DoD
// Interoperability CA 2 signed by the Federal Bridge CA 2016.
const PEMDoDInteropCA2SignedByFederalBridgeCA2016 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            05:d1:6f:14:b3:c9:52:02:58:ab:27:af:8e:14:a9:72:c7:d5:b3:91
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2016
        Validity
            Not Before: May 10 15:35:12 2017 GMT
            Not After : Aug 15 15:34:38 2019 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.39

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2016.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36, 2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.3.2.1.12.4, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.12.5, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.3.2.1.12.9, 2.16.840.1.101.3.2.1.3.18:2.16.840.1.101.3.2.1.12.6, 2.16.840.1.101.3.2.1.3.19:2.16.840.1.101.3.2.1.12.7, 2.16.840.1.101.3.2.1.3.20:2.16.840.1.101.3.2.1.12.8, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.12.10
            X509v3 Name Constraints:
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil
                  DirName: C = US, O = U.S. Government, OU = ECA

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints:
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Inhibit Any Policy:
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:23:B0:B3:7D:16:54:D4:02:56:76:EB:3A:BE:A9:6B:2F:43:7B:28:16

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2016.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        a3:14:ba:01:a3:f9:45:88:5d:c7:52:e3:ff:3b:16:15:fc:af:
        87:d8:4c:67:f9:ff:30:2d:5a:21:6a:5f:22:d0:06:c5:b6:0b:
        4c:42:fa:0a:45:01:c3:62:f8:34:86:1e:11:3a:30:e5:cc:b7:
        76:b7:51:3c:b5:28:08:75:cf:c4:aa:05:ce:0e:04:d9:57:b8:
        9f:06:8c:b2:28:9c:37:9a:ba:20:92:5b:62:83:e2:27:be:56:
        b6:48:d2:a0:7c:c2:e9:3f:e0:13:4a:11:cc:bd:98:0a:bb:ae:
        65:82:91:32:06:f5:15:5a:69:37:3f:77:f5:63:de:63:04:92:
        51:4d:fa:4a:77:a2:e6:6e:11:a3:64:d5:09:1a:2f:96:19:17:
        10:b3:e2:de:4d:9b:f8:64:23:2c:16:33:83:1b:0f:37:e3:15:
        03:83:83:2a:29:1a:c3:5f:d5:f0:16:ff:7e:fe:61:9d:e5:65:
        c9:27:14:ea:d0:f5:69:1b:b1:93:7b:da:d3:22:8b:53:07:18:
        8f:ee:ca:a6:03:68:02:89:f6:33:02:2a:a2:36:94:94:c1:73:
        5b:75:c2:8f:02:9b:c7:8a:68:57:af:e5:2d:07:7e:ca:56:c6:
        25:2f:bc:7a:fb:77:94:88:66:6c:10:47:72:21:29:10:4d:cc:
        0c:e1:ec:74
-----BEGIN CERTIFICATE-----
MIIHADCCBeigAwIBAgIUBdFvFLPJUgJYqyevjhSpcsfVs5EwDQYJKoZIhvcNAQEL
BQAwVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsG
A1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxNjAeFw0x
NzA1MTAxNTM1MTJaFw0xOTA4MTUxNTM0MzhaMGwxCzAJBgNVBAYTAlVTMRgwFgYD
VQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJ
MScwJQYDVQQDEx5Eb0QgSW50ZXJvcGVyYWJpbGl0eSBSb290IENBIDIwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD3xtCDk+YLgynoKDu2SuCsjJ60VcPf
GH7is3NytGihZtiYY+q+j17ADhGtf9LzpSUv7n6j2JCNSyFg098/hRv8Qxe9rM3R
/uAt/r1GHz6YVojfB0ySBLQF1RXgmqTDUdMKeNg8/Fwc5c0jSZdQPrG0tqJTUjQJ
MQOME+fpTcP7A9wCo1rVbWuvFivUTv57oEE47UuvJjW1nIlpDuklzbFNM6+ObWWR
KOXc/XLo+KYxM5L/8AKjUE6Bwfg065UpCaXaq2Bh/eq5T0oxipdm+MMA0tKGo0JD
07t5Jy5vtbJl5UuNSa8QsdJbdXcQdOMW8iRneAy29jYPQu//o8C7xl61AgMBAAGj
ggOtMIIDqTAPBgNVHRMBAf8EBTADAQH/MIGIBgNVHSAEgYAwfjAMBgpghkgBZQMC
AQMDMAwGCmCGSAFlAwIBAwwwDAYKYIZIAWUDAgEDJTAMBgpghkgBZQMCAQMNMAwG
CmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDEjAMBgpghkgBZQMCAQMTMAwGCmCGSAFl
AwIBAxQwDAYKYIZIAWUDAgEDJzBTBggrBgEFBQcBAQRHMEUwQwYIKwYBBQUHMAKG
N2h0dHA6Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9jYUNlcnRzSXNzdWVkVG9mYmNh
MjAxNi5wN2MwggEOBgNVHSEEggEFMIIBATAXBgpghkgBZQMCAQMDBglghkgBZQIB
CycwFwYKYIZIAWUDAgEDDAYJYIZIAWUCAQsqMBcGCmCGSAFlAwIBAyUGCWCGSAFl
AgELJDAYBgpghkgBZQMCAQMDBgpghkgBZQMCAQwEMBgGCmCGSAFlAwIBAwwGCmCG
SAFlAwIBDAUwGAYKYIZIAWUDAgEDJQYKYIZIAWUDAgEMCTAYBgpghkgBZQMCAQMS
BgpghkgBZQMCAQwGMBgGCmCGSAFlAwIBAxMGCmCGSAFlAwIBDAcwGAYKYIZIAWUD
AgEDFAYKYIZIAWUDAgEMCDAYBgpghkgBZQMCAQMMBgpghkgBZQMCAQwKMIGfBgNV
HR4EgZcwgZSggZEwOaQ3MDUxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdv
dmVybm1lbnQxDDAKBgNVBAsTA0RvRDAZpBcwFTETMBEGCgmSJomT8ixkARkWA21p
bDA5pDcwNTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEM
MAoGA1UECxMDRUNBMFoGCCsGAQUFBwELBE4wTDBKBggrBgEFBQcwBYY+aHR0cDov
L2NybC5kaXNhLm1pbC9pc3N1ZWRieS9ET0RJTlRFUk9QRVJBQklMSVRZUk9PVENB
Ml9JQi5wN2MwDwYDVR0kBAgwBoABAIEBADAKBgNVHTYEAwIBADAOBgNVHQ8BAf8E
BAMCAQYwHwYDVR0jBBgwFoAUI7CzfRZU1AJWdus6vqlrL0N7KBYwOQYDVR0fBDIw
MDAuoCygKoYoaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2ZiY2EyMDE2LmNy
bDAdBgNVHQ4EFgQU//iuE4uSK3mSQaN2XCyBnprFnHgwDQYJKoZIhvcNAQELBQAD
ggEBAKMUugGj+UWIXcdS4/87FhX8r4fYTGf5/zAtWiFqXyLQBsW2C0xC+gpFAcNi
+DSGHhE6MOXMt3a3UTy1KAh1z8SqBc4OBNlXuJ8GjLIonDeauiCSW2KD4ie+VrZI
0qB8wuk/4BNKEcy9mAq7rmWCkTIG9RVaaTc/d/Vj3mMEklFN+kp3ouZuEaNk1Qka
L5YZFxCz4t5Nm/hkIywWM4MbDzfjFQODgyopGsNf1fAW/37+YZ3lZcknFOrQ9Wkb
sZN72tMii1MHGI/uyqYDaAKJ9jMCKqI2lJTBc1t1wo8Cm8eKaFev5S0HfspWxiUv
vHr7d5SIZmwQR3IhKRBNzAzh7HQ=
-----END CERTIFICATE-----
`

// PEMDoDInteropCA2SignedByFederalBridgeCA is a certificate for the DoD
// Interoperability CA 2 signed by the Federal Bridge CA.
const PEMDoDInteropCA2SignedByFederalBridgeCA = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4515 (0x11a3)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA
        Validity
            Not Before: May 21 16:05:18 2013 GMT
            Not After : May 21 16:03:30 2016 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36
            X509v3 Name Constraints: critical
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:C4:9D:FC:9D:5D:3A:5D:05:7A:BF:02:81:EC:DB:49:70:15:C7:B2:72

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        0d:57:8a:eb:a0:c6:17:d6:b0:f3:36:86:41:b9:9f:20:81:7b:
        f0:a8:c1:d0:77:60:5a:77:d8:f9:3a:be:92:e5:c3:c8:ed:a1:
        58:e8:30:46:c7:ee:e3:33:78:97:6a:e6:31:1c:b7:9c:eb:28:
        80:11:b4:de:12:d4:a8:48:10:b9:58:32:ab:2b:e8:77:39:22:
        f0:cb:83:05:1a:a6:ad:87:f5:e4:49:cd:09:da:b6:a1:bb:63:
        cf:b8:86:fb:ab:f9:54:6e:14:77:8e:13:ee:f2:ff:a4:9b:81:
        3e:ef:c1:d3:16:60:74:76:2b:a3:af:ef:77:e4:2a:d8:fb:d8:
        c5:e2:cc:d3:d0:49:7b:ac:26:64:3b:ed:33:a6:ab:ae:d1:62:
        5c:c1:fd:e3:0b:ae:ef:2a:9d:75:12:04:63:d1:05:b5:0f:15:
        0e:07:c1:4b:04:0c:db:b8:30:0b:e2:93:2f:2c:a8:2e:f0:19:
        2c:13:29:28:d7:d6:40:00:56:f5:5a:06:11:89:03:11:cb:c8:
        ee:a7:1c:27:0c:fc:76:64:9f:da:f9:f9:c6:6a:03:f2:07:09:
        52:9e:09:c8:04:70:d9:bd:de:12:8b:bb:ef:91:06:88:8d:3e:
        92:3e:31:c1:e0:ff:ea:a6:c7:15:64:69:6f:a6:f4:3c:34:13:
        da:72:31:98
-----BEGIN CERTIFICATE-----
MIIFpjCCBI6gAwIBAgICEaMwDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEaMBgGA1UE
AxMRRmVkZXJhbCBCcmlkZ2UgQ0EwHhcNMTMwNTIxMTYwNTE4WhcNMTYwNTIxMTYw
MzMwWjBsMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQww
CgYDVQQLEwNEb0QxDDAKBgNVBAsTA1BLSTEnMCUGA1UEAxMeRG9EIEludGVyb3Bl
cmFiaWxpdHkgUm9vdCBDQSAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA98bQg5PmC4Mp6Cg7tkrgrIyetFXD3xh+4rNzcrRooWbYmGPqvo9ewA4RrX/S
86UlL+5+o9iQjUshYNPfP4Ub/EMXvazN0f7gLf69Rh8+mFaI3wdMkgS0BdUV4Jqk
w1HTCnjYPPxcHOXNI0mXUD6xtLaiU1I0CTEDjBPn6U3D+wPcAqNa1W1rrxYr1E7+
e6BBOO1LryY1tZyJaQ7pJc2xTTOvjm1lkSjl3P1y6PimMTOS//ACo1BOgcH4NOuV
KQml2qtgYf3quU9KMYqXZvjDANLShqNCQ9O7eScub7WyZeVLjUmvELHSW3V3EHTj
FvIkZ3gMtvY2D0Lv/6PAu8ZetQIDAQABo4ICajCCAmYwDwYDVR0TAQH/BAUwAwEB
/zBPBgNVHSAESDBGMAwGCmCGSAFlAwIBAwMwDAYKYIZIAWUDAgEDDDAMBgpghkgB
ZQMCAQMlMAwGCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgEDETBPBggrBgEFBQcBAQRD
MEEwPwYIKwYBBQUHMAKGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9jYUNl
cnRzSXNzdWVkVG9mYmNhLnA3YzBUBgNVHSEETTBLMBcGCmCGSAFlAwIBAwMGCWCG
SAFlAgELJzAXBgpghkgBZQMCAQMMBglghkgBZQIBCyowFwYKYIZIAWUDAgEDJQYJ
YIZIAWUCAQskMGQGA1UdHgEB/wRaMFigVjA5pDcwNTELMAkGA1UEBhMCVVMxGDAW
BgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMBmkFzAVMRMwEQYK
CZImiZPyLGQBGRYDbWlsMFoGCCsGAQUFBwELBE4wTDBKBggrBgEFBQcwBYY+aHR0
cDovL2NybC5kaXNhLm1pbC9pc3N1ZWRieS9ET0RJTlRFUk9QRVJBQklMSVRZUk9P
VENBMl9JQi5wN2MwEgYDVR0kAQH/BAgwBoABAIEBADAOBgNVHQ8BAf8EBAMCAQYw
HwYDVR0jBBgwFoAUxJ38nV06XQV6vwKB7NtJcBXHsnIwNQYDVR0fBC4wLDAqoCig
JoYkaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2ZiY2EuY3JsMB0GA1UdDgQW
BBT/+K4Ti5IreZJBo3ZcLIGemsWceDANBgkqhkiG9w0BAQsFAAOCAQEADVeK66DG
F9aw8zaGQbmfIIF78KjB0HdgWnfY+Tq+kuXDyO2hWOgwRsfu4zN4l2rmMRy3nOso
gBG03hLUqEgQuVgyqyvodzki8MuDBRqmrYf15EnNCdq2obtjz7iG+6v5VG4Ud44T
7vL/pJuBPu/B0xZgdHYro6/vd+Qq2PvYxeLM09BJe6wmZDvtM6arrtFiXMH94wuu
7yqddRIEY9EFtQ8VDgfBSwQM27gwC+KTLyyoLvAZLBMpKNfWQABW9VoGEYkDEcvI
7qccJwz8dmSf2vn5xmoD8gcJUp4JyARw2b3eEou775EGiI0+kj4xweD/6qbHFWRp
b6b0PDQT2nIxmA==
-----END CERTIFICATE-----
`

// HexHashPEMDoDInteropCA2SignedByFederalBridgeCA is the hex SHA256 fingerprint
// of PEMDoDInteropCA2SignedByFederalBridgeCA.
const HexHashPEMDoDInteropCA2SignedByFederalBridgeCA = "76eb46d3a0808c7ef85fcd7128c2611e840c8299b836cc88d372564e1be1e96f"

// PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906 is the certificate for
// the DoD Interoperability CA 2 signed by the Federal Bridge CA 2013 with the
// serial number 906.
const PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 906 (0x38a)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Validity
            Not Before: Jan 29 14:20:36 2014 GMT
            Not After : May 21 13:12:52 2016 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2013.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36
            X509v3 Name Constraints: critical
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2013.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        49:4f:71:1e:75:c1:69:ff:ed:07:ce:4a:01:71:4e:39:63:9a:
        59:66:c5:b9:84:04:a9:5c:35:76:33:65:f6:d2:56:bb:6e:8f:
        4e:63:24:a0:c5:5e:b8:67:1b:c5:9f:a2:e5:44:83:c1:b7:6b:
        15:ee:4e:21:9a:56:37:3d:15:68:6c:96:24:3b:88:41:d2:23:
        db:ed:b2:ce:6d:a5:56:66:75:f3:a7:b5:78:86:c1:a3:6f:3e:
        b7:d9:88:45:23:7e:92:7e:52:86:31:b1:3d:f1:a3:7e:3f:47:
        37:df:60:fe:a1:4a:0f:fb:80:c6:f6:0c:b6:da:73:20:d4:d2:
        1e:21:7e:37:fc:dd:60:a8:98:60:37:d4:1a:8b:fb:ea:7b:c1:
        89:db:32:43:f1:ab:1d:bc:ae:73:9b:45:9d:1e:5d:72:95:ac:
        47:3b:09:81:1d:c4:b3:ed:1a:49:ec:f9:5a:57:17:f5:94:67:
        a9:66:fa:59:4a:20:2d:8f:ad:d0:d0:16:69:74:48:49:e2:68:
        2d:e6:fc:0c:87:12:c0:db:13:3d:73:73:0f:1e:ff:c4:80:b7:
        df:ff:f8:b3:44:43:1c:71:a5:7c:b6:31:fa:59:78:f9:76:c0:
        75:65:e0:d5:65:63:ea:f0:e5:ba:b9:dd:d5:56:b6:b8:e1:93:
        c6:68:af:c6
-----BEGIN CERTIFICATE-----
MIIFszCCBJugAwIBAgICA4owDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UE
AxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxMzAeFw0xNDAxMjkxNDIwMzZaFw0xNjA1
MjExMzEyNTJaMGwxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMScwJQYDVQQDEx5Eb0QgSW50
ZXJvcGVyYWJpbGl0eSBSb290IENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD3xtCDk+YLgynoKDu2SuCsjJ60VcPfGH7is3NytGihZtiYY+q+j17A
DhGtf9LzpSUv7n6j2JCNSyFg098/hRv8Qxe9rM3R/uAt/r1GHz6YVojfB0ySBLQF
1RXgmqTDUdMKeNg8/Fwc5c0jSZdQPrG0tqJTUjQJMQOME+fpTcP7A9wCo1rVbWuv
FivUTv57oEE47UuvJjW1nIlpDuklzbFNM6+ObWWRKOXc/XLo+KYxM5L/8AKjUE6B
wfg065UpCaXaq2Bh/eq5T0oxipdm+MMA0tKGo0JD07t5Jy5vtbJl5UuNSa8QsdJb
dXcQdOMW8iRneAy29jYPQu//o8C7xl61AgMBAAGjggJyMIICbjAPBgNVHRMBAf8E
BTADAQH/ME8GA1UdIARIMEYwDAYKYIZIAWUDAgEDAzAMBgpghkgBZQMCAQMMMAwG
CmCGSAFlAwIBAyUwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMFMGCCsGAQUF
BwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdl
L2NhQ2VydHNJc3N1ZWRUb2ZiY2EyMDEzLnA3YzBUBgNVHSEETTBLMBcGCmCGSAFl
AwIBAwMGCWCGSAFlAgELJzAXBgpghkgBZQMCAQMMBglghkgBZQIBCyowFwYKYIZI
AWUDAgEDJQYJYIZIAWUCAQskMGQGA1UdHgEB/wRaMFigVjA5pDcwNTELMAkGA1UE
BhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMBmk
FzAVMRMwEQYKCZImiZPyLGQBGRYDbWlsMFoGCCsGAQUFBwELBE4wTDBKBggrBgEF
BQcwBYY+aHR0cDovL2NybC5kaXNhLm1pbC9pc3N1ZWRieS9ET0RJTlRFUk9QRVJB
QklMSVRZUk9PVENBMl9JQi5wN2MwEgYDVR0kAQH/BAgwBoABAIEBADAOBgNVHQ8B
Af8EBAMCAQYwHwYDVR0jBBgwFoAUu850cYM0TlkyRRVfQGBg3CuwtOQwOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2ZiY2EyMDEz
LmNybDAdBgNVHQ4EFgQU//iuE4uSK3mSQaN2XCyBnprFnHgwDQYJKoZIhvcNAQEL
BQADggEBAElPcR51wWn/7QfOSgFxTjljmllmxbmEBKlcNXYzZfbSVrtuj05jJKDF
XrhnG8WfouVEg8G3axXuTiGaVjc9FWhsliQ7iEHSI9vtss5tpVZmdfOntXiGwaNv
PrfZiEUjfpJ+UoYxsT3xo34/RzffYP6hSg/7gMb2DLbacyDU0h4hfjf83WComGA3
1BqL++p7wYnbMkPxqx28rnObRZ0eXXKVrEc7CYEdxLPtGkns+VpXF/WUZ6lm+llK
IC2PrdDQFml0SEniaC3m/AyHEsDbEz1zcw8e/8SAt9//+LNEQxxxpXy2MfpZePl2
wHVl4NVlY+rw5bq53dVWtrjhk8Zor8Y=
-----END CERTIFICATE-----
`

// HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906 is the hex SHA256
// fingerprint of PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906.
const HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906 = "f1ca80e8c4420f0cab6c2f8b04b4deda19b1cea1f6869e16907674209035d5a1"

// PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 is the certificate for
// the DoD Interoperability CA 2 signed by the Federal Bridge CA 2013 with the
// serial number 8225.
const PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 8225 (0x2021)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Validity
            Not Before: Apr  6 17:00:49 2016 GMT
            Not After : May 21 13:56:52 2016 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2013.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36
            X509v3 Name Constraints:
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Inhibit Any Policy:
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2013.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        3b:cc:08:c7:bf:ca:a7:6d:88:45:23:1b:7a:01:d3:ce:c9:f6:
        4e:29:43:73:34:a5:ed:2a:f3:fa:db:2f:14:ee:b7:d8:08:34:
        78:a8:32:6e:6f:61:ea:d1:44:f2:6a:c3:a7:3c:ce:46:72:2d:
        37:78:28:c2:e6:ac:18:a9:45:55:9c:65:1a:45:8b:71:d5:23:
        69:96:63:a0:f8:c8:3d:cd:6e:70:63:fa:9f:1b:b8:cb:f5:9c:
        01:ba:ec:0a:c6:32:85:db:8e:57:f8:78:f2:08:a6:1a:99:34:
        d6:46:96:bd:15:f8:dc:64:c0:c9:9c:95:34:5d:fe:2a:9f:9c:
        e8:fc:de:73:36:1d:1b:98:f4:3a:51:37:14:c4:7e:33:91:1e:
        88:c3:08:c8:95:dd:ae:f1:f9:b9:f3:77:05:41:4a:56:3f:b9:
        69:7b:69:99:ca:54:50:a9:c0:29:84:f8:69:5e:99:89:ba:d1:
        7e:04:c2:10:91:a7:7e:14:9a:b6:ad:ad:62:5b:e3:5d:44:90:
        a5:75:e5:04:f8:a4:83:6e:c4:5d:67:4d:52:f3:12:1f:c8:ec:
        92:6b:a2:d9:1e:a6:b0:12:fc:36:60:a4:8d:c7:4a:4c:6a:c1:
        d9:d0:7d:6e:20:85:22:5f:91:5f:9f:76:9a:db:4c:01:03:03:
        5c:b6:70:59
-----BEGIN CERTIFICATE-----
MIIFvDCCBKSgAwIBAgICICEwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UE
AxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxMzAeFw0xNjA0MDYxNzAwNDlaFw0xNjA1
MjExMzU2NTJaMGwxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMScwJQYDVQQDEx5Eb0QgSW50
ZXJvcGVyYWJpbGl0eSBSb290IENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD3xtCDk+YLgynoKDu2SuCsjJ60VcPfGH7is3NytGihZtiYY+q+j17A
DhGtf9LzpSUv7n6j2JCNSyFg098/hRv8Qxe9rM3R/uAt/r1GHz6YVojfB0ySBLQF
1RXgmqTDUdMKeNg8/Fwc5c0jSZdQPrG0tqJTUjQJMQOME+fpTcP7A9wCo1rVbWuv
FivUTv57oEE47UuvJjW1nIlpDuklzbFNM6+ObWWRKOXc/XLo+KYxM5L/8AKjUE6B
wfg065UpCaXaq2Bh/eq5T0oxipdm+MMA0tKGo0JD07t5Jy5vtbJl5UuNSa8QsdJb
dXcQdOMW8iRneAy29jYPQu//o8C7xl61AgMBAAGjggJ7MIICdzAPBgNVHRMBAf8E
BTADAQH/ME8GA1UdIARIMEYwDAYKYIZIAWUDAgEDAzAMBgpghkgBZQMCAQMMMAwG
CmCGSAFlAwIBAyUwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMFMGCCsGAQUF
BwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdl
L2NhQ2VydHNJc3N1ZWRUb2ZiY2EyMDEzLnA3YzBUBgNVHSEETTBLMBcGCmCGSAFl
AwIBAwMGCWCGSAFlAgELJzAXBgpghkgBZQMCAQMMBglghkgBZQIBCyowFwYKYIZI
AWUDAgEDJQYJYIZIAWUCAQskMGEGA1UdHgRaMFigVjA5pDcwNTELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMBmkFzAV
MRMwEQYKCZImiZPyLGQBGRYDbWlsMFoGCCsGAQUFBwELBE4wTDBKBggrBgEFBQcw
BYY+aHR0cDovL2NybC5kaXNhLm1pbC9pc3N1ZWRieS9ET0RJTlRFUk9QRVJBQklM
SVRZUk9PVENBMl9JQi5wN2MwEgYDVR0kAQH/BAgwBoABAIEBADAKBgNVHTYEAwIB
ADAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUu850cYM0TlkyRRVfQGBg3Cuw
tOQwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdl
L2ZiY2EyMDEzLmNybDAdBgNVHQ4EFgQU//iuE4uSK3mSQaN2XCyBnprFnHgwDQYJ
KoZIhvcNAQELBQADggEBADvMCMe/yqdtiEUjG3oB087J9k4pQ3M0pe0q8/rbLxTu
t9gINHioMm5vYerRRPJqw6c8zkZyLTd4KMLmrBipRVWcZRpFi3HVI2mWY6D4yD3N
bnBj+p8buMv1nAG67ArGMoXbjlf4ePIIphqZNNZGlr0V+NxkwMmclTRd/iqfnOj8
3nM2HRuY9DpRNxTEfjORHojDCMiV3a7x+bnzdwVBSlY/uWl7aZnKVFCpwCmE+Gle
mYm60X4EwhCRp34UmratrWJb411EkKV15QT4pINuxF1nTVLzEh/I7JJrotkeprAS
/DZgpI3HSkxqwdnQfW4ghSJfkV+fdprbTAEDA1y2cFk=
-----END CERTIFICATE-----
`

// HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 is the hex
// SHA256 fingerprint of PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225.
const HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 = "15fc3efd4294832257ba5a24a232fee2244880dcdc297a2872a6b75727557b1f"

// PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 is the certificate for
// the DoD Interoperability CA 2 signed by the Federal Bridge CA 2013 with the
// serial number 8844.
const PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 8844 (0x228c)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Validity
            Not Before: May 18 17:25:34 2016 GMT
            Not After : Aug 21 21:24:28 2016 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2013.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36
            X509v3 Name Constraints:
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints:
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Inhibit Any Policy:
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2013.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        1a:b0:c5:ce:3c:14:22:41:a3:70:5a:ed:d3:3a:24:9a:a1:61:
        ee:5b:0e:7a:46:0c:e0:7d:e8:8f:9c:dc:38:6b:27:83:a3:dd:
        f4:38:2f:09:39:b5:63:0b:ac:25:2c:4e:1d:ad:39:fe:92:7b:
        2d:a0:6e:02:d0:a8:21:4e:c1:fa:54:ec:7c:7d:08:ff:69:c7:
        05:e7:f7:71:c8:65:8d:6c:c8:bf:d7:c7:17:98:d3:a6:c2:d6:
        a3:bc:b5:37:cd:57:bb:58:35:83:22:5d:3e:8e:9d:dd:8c:f6:
        e4:36:2a:95:5c:50:73:10:99:1a:c0:d9:f7:e0:1d:34:b0:aa:
        d5:0d:ae:27:9f:3c:a2:c7:5e:57:20:0b:0e:51:17:58:d0:aa:
        dc:93:35:93:15:61:6b:c6:13:97:4a:fe:e2:f6:0f:11:ae:0c:
        39:66:9c:24:14:d7:16:00:60:10:80:38:9e:b8:12:46:89:70:
        37:21:73:74:6d:db:c6:7c:41:15:27:7a:1a:a3:d1:3d:08:26:
        65:17:aa:b1:ca:11:af:6c:67:60:4a:ca:3c:20:bc:e6:53:27:
        37:bb:de:26:b1:66:da:b5:93:1c:23:e5:27:36:99:18:bb:fb:
        7d:1f:3c:01:4f:2d:da:e2:3a:7e:75:8b:0c:a9:d7:30:3b:e9:
        19:28:16:d0
-----BEGIN CERTIFICATE-----
MIIFuTCCBKGgAwIBAgICIowwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UE
AxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxMzAeFw0xNjA1MTgxNzI1MzRaFw0xNjA4
MjEyMTI0MjhaMGwxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMScwJQYDVQQDEx5Eb0QgSW50
ZXJvcGVyYWJpbGl0eSBSb290IENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD3xtCDk+YLgynoKDu2SuCsjJ60VcPfGH7is3NytGihZtiYY+q+j17A
DhGtf9LzpSUv7n6j2JCNSyFg098/hRv8Qxe9rM3R/uAt/r1GHz6YVojfB0ySBLQF
1RXgmqTDUdMKeNg8/Fwc5c0jSZdQPrG0tqJTUjQJMQOME+fpTcP7A9wCo1rVbWuv
FivUTv57oEE47UuvJjW1nIlpDuklzbFNM6+ObWWRKOXc/XLo+KYxM5L/8AKjUE6B
wfg065UpCaXaq2Bh/eq5T0oxipdm+MMA0tKGo0JD07t5Jy5vtbJl5UuNSa8QsdJb
dXcQdOMW8iRneAy29jYPQu//o8C7xl61AgMBAAGjggJ4MIICdDAPBgNVHRMBAf8E
BTADAQH/ME8GA1UdIARIMEYwDAYKYIZIAWUDAgEDAzAMBgpghkgBZQMCAQMMMAwG
CmCGSAFlAwIBAyUwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMFMGCCsGAQUF
BwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdl
L2NhQ2VydHNJc3N1ZWRUb2ZiY2EyMDEzLnA3YzBUBgNVHSEETTBLMBcGCmCGSAFl
AwIBAwMGCWCGSAFlAgELJzAXBgpghkgBZQMCAQMMBglghkgBZQIBCyowFwYKYIZI
AWUDAgEDJQYJYIZIAWUCAQskMGEGA1UdHgRaMFigVjA5pDcwNTELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMBmkFzAV
MRMwEQYKCZImiZPyLGQBGRYDbWlsMFoGCCsGAQUFBwELBE4wTDBKBggrBgEFBQcw
BYY+aHR0cDovL2NybC5kaXNhLm1pbC9pc3N1ZWRieS9ET0RJTlRFUk9QRVJBQklM
SVRZUk9PVENBMl9JQi5wN2MwDwYDVR0kBAgwBoABAIEBADAKBgNVHTYEAwIBADAO
BgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUu850cYM0TlkyRRVfQGBg3CuwtOQw
OQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2Zi
Y2EyMDEzLmNybDAdBgNVHQ4EFgQU//iuE4uSK3mSQaN2XCyBnprFnHgwDQYJKoZI
hvcNAQELBQADggEBABqwxc48FCJBo3Ba7dM6JJqhYe5bDnpGDOB96I+c3DhrJ4Oj
3fQ4Lwk5tWMLrCUsTh2tOf6Sey2gbgLQqCFOwfpU7Hx9CP9pxwXn93HIZY1syL/X
xxeY06bC1qO8tTfNV7tYNYMiXT6Ond2M9uQ2KpVcUHMQmRrA2ffgHTSwqtUNrief
PKLHXlcgCw5RF1jQqtyTNZMVYWvGE5dK/uL2DxGuDDlmnCQU1xYAYBCAOJ64EkaJ
cDchc3Rt28Z8QRUnehqj0T0IJmUXqrHKEa9sZ2BKyjwgvOZTJze73iaxZtq1kxwj
5Sc2mRi7+30fPAFPLdriOn51iwyp1zA76RkoFtA=
-----END CERTIFICATE-----
`

// HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 is the hex
// SHA256 fingerprint of PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844.
const HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 = "ce1a4657b4649ba5701126c740642a56c464225eec3bf398a1a45b57e33356b6"

// PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 is the certificate for
// the Dod Interoperability CA 2 signed by the Federal Bridge CA 2013 with the
// serial number 9644.
const PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 9644 (0x25ac)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Validity
            Not Before: Aug 15 15:47:46 2016 GMT
            Not After : Aug 15 15:47:23 2019 GMT
        Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:f7:c6:d0:83:93:e6:0b:83:29:e8:28:3b:b6:4a:
                    e0:ac:8c:9e:b4:55:c3:df:18:7e:e2:b3:73:72:b4:
                    68:a1:66:d8:98:63:ea:be:8f:5e:c0:0e:11:ad:7f:
                    d2:f3:a5:25:2f:ee:7e:a3:d8:90:8d:4b:21:60:d3:
                    df:3f:85:1b:fc:43:17:bd:ac:cd:d1:fe:e0:2d:fe:
                    bd:46:1f:3e:98:56:88:df:07:4c:92:04:b4:05:d5:
                    15:e0:9a:a4:c3:51:d3:0a:78:d8:3c:fc:5c:1c:e5:
                    cd:23:49:97:50:3e:b1:b4:b6:a2:53:52:34:09:31:
                    03:8c:13:e7:e9:4d:c3:fb:03:dc:02:a3:5a:d5:6d:
                    6b:af:16:2b:d4:4e:fe:7b:a0:41:38:ed:4b:af:26:
                    35:b5:9c:89:69:0e:e9:25:cd:b1:4d:33:af:8e:6d:
                    65:91:28:e5:dc:fd:72:e8:f8:a6:31:33:92:ff:f0:
                    02:a3:50:4e:81:c1:f8:34:eb:95:29:09:a5:da:ab:
                    60:61:fd:ea:b9:4f:4a:31:8a:97:66:f8:c3:00:d2:
                    d2:86:a3:42:43:d3:bb:79:27:2e:6f:b5:b2:65:e5:
                    4b:8d:49:af:10:b1:d2:5b:75:77:10:74:e3:16:f2:
                    24:67:78:0c:b6:f6:36:0f:42:ef:ff:a3:c0:bb:c6:
                    5e:b5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.39

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2013.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.2.1.11.39, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.2.1.11.42, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.2.1.11.36, 2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.3.2.1.12.4, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.12.5, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.3.2.1.12.9, 2.16.840.1.101.3.2.1.3.18:2.16.840.1.101.3.2.1.12.6, 2.16.840.1.101.3.2.1.3.19:2.16.840.1.101.3.2.1.12.7, 2.16.840.1.101.3.2.1.3.20:2.16.840.1.101.3.2.1.12.8, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.12.10
            X509v3 Name Constraints:
                Permitted:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: DC = mil
                  DirName: C = US, O = U.S. Government, OU = ECA

            Subject Information Access:
                CA Repository - URI:http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c

            X509v3 Policy Constraints:
                Require Explicit Policy:0, Inhibit Policy Mapping:0
            X509v3 Inhibit Any Policy:
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2013.crl

            X509v3 Subject Key Identifier:
                FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78
    Signature Algorithm: sha256WithRSAEncryption
        85:a2:4c:ab:e0:9b:d4:27:69:4e:e0:f4:05:6f:2e:55:90:5a:
        ce:8f:6d:8e:03:43:9f:23:83:33:91:de:64:6d:b3:fd:3b:57:
        84:59:04:d3:0f:83:e1:56:d2:34:73:d1:c6:9f:a7:46:c5:70:
        93:02:db:cb:95:c0:0d:6c:38:ce:be:81:13:48:4b:af:8f:a7:
        5c:1d:cd:7d:3f:e4:09:db:83:df:75:5d:91:8a:b2:ef:5c:3a:
        e7:05:8f:cd:27:a3:f1:fd:f0:b5:3c:60:28:76:3a:f7:bb:c6:
        b5:a6:36:27:d4:7a:5e:6c:92:dc:f9:20:ce:db:84:67:69:f8:
        c0:82:59:98:8d:5d:50:81:7e:90:06:75:61:9e:ec:e4:87:58:
        3c:e7:ed:8c:d8:da:45:24:80:e5:3e:2d:2a:3a:ea:1f:29:e3:
        bc:dd:94:b2:bc:d8:58:17:e2:3f:99:b8:c4:67:35:44:f5:24:
        f3:d0:57:68:b5:91:af:b2:f7:4a:1c:15:7c:1b:44:2b:d9:84:
        4c:85:b7:87:d9:be:10:c6:26:1c:ba:e9:f0:ad:6d:4d:8e:d2:
        a9:2d:fc:ec:3c:bf:ae:ce:1d:17:c6:d4:d8:60:33:3f:76:61:
        75:66:f6:be:78:b6:47:ac:ce:4a:43:44:14:56:bf:81:92:10:
        82:49:c1:da
-----BEGIN CERTIFICATE-----
MIIG7jCCBdagAwIBAgICJawwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UE
AxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxMzAeFw0xNjA4MTUxNTQ3NDZaFw0xOTA4
MTUxNTQ3MjNaMGwxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMScwJQYDVQQDEx5Eb0QgSW50
ZXJvcGVyYWJpbGl0eSBSb290IENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD3xtCDk+YLgynoKDu2SuCsjJ60VcPfGH7is3NytGihZtiYY+q+j17A
DhGtf9LzpSUv7n6j2JCNSyFg098/hRv8Qxe9rM3R/uAt/r1GHz6YVojfB0ySBLQF
1RXgmqTDUdMKeNg8/Fwc5c0jSZdQPrG0tqJTUjQJMQOME+fpTcP7A9wCo1rVbWuv
FivUTv57oEE47UuvJjW1nIlpDuklzbFNM6+ObWWRKOXc/XLo+KYxM5L/8AKjUE6B
wfg065UpCaXaq2Bh/eq5T0oxipdm+MMA0tKGo0JD07t5Jy5vtbJl5UuNSa8QsdJb
dXcQdOMW8iRneAy29jYPQu//o8C7xl61AgMBAAGjggOtMIIDqTAPBgNVHRMBAf8E
BTADAQH/MIGIBgNVHSAEgYAwfjAMBgpghkgBZQMCAQMDMAwGCmCGSAFlAwIBAwww
DAYKYIZIAWUDAgEDJTAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZI
AWUDAgEDEjAMBgpghkgBZQMCAQMTMAwGCmCGSAFlAwIBAxQwDAYKYIZIAWUDAgED
JzBTBggrBgEFBQcBAQRHMEUwQwYIKwYBBQUHMAKGN2h0dHA6Ly9odHRwLmZwa2ku
Z292L2JyaWRnZS9jYUNlcnRzSXNzdWVkVG9mYmNhMjAxMy5wN2MwggEOBgNVHSEE
ggEFMIIBATAXBgpghkgBZQMCAQMDBglghkgBZQIBCycwFwYKYIZIAWUDAgEDDAYJ
YIZIAWUCAQsqMBcGCmCGSAFlAwIBAyUGCWCGSAFlAgELJDAYBgpghkgBZQMCAQMD
BgpghkgBZQMCAQwEMBgGCmCGSAFlAwIBAwwGCmCGSAFlAwIBDAUwGAYKYIZIAWUD
AgEDJQYKYIZIAWUDAgEMCTAYBgpghkgBZQMCAQMSBgpghkgBZQMCAQwGMBgGCmCG
SAFlAwIBAxMGCmCGSAFlAwIBDAcwGAYKYIZIAWUDAgEDFAYKYIZIAWUDAgEMCDAY
BgpghkgBZQMCAQMMBgpghkgBZQMCAQwKMIGfBgNVHR4EgZcwgZSggZEwOaQ3MDUx
CzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT
A0RvRDAZpBcwFTETMBEGCgmSJomT8ixkARkWA21pbDA5pDcwNTELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRUNBMFoGCCsG
AQUFBwELBE4wTDBKBggrBgEFBQcwBYY+aHR0cDovL2NybC5kaXNhLm1pbC9pc3N1
ZWRieS9ET0RJTlRFUk9QRVJBQklMSVRZUk9PVENBMl9JQi5wN2MwDwYDVR0kBAgw
BoABAIEBADAKBgNVHTYEAwIBADAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAU
u850cYM0TlkyRRVfQGBg3CuwtOQwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2h0
dHAuZnBraS5nb3YvYnJpZGdlL2ZiY2EyMDEzLmNybDAdBgNVHQ4EFgQU//iuE4uS
K3mSQaN2XCyBnprFnHgwDQYJKoZIhvcNAQELBQADggEBAIWiTKvgm9QnaU7g9AVv
LlWQWs6PbY4DQ58jgzOR3mRts/07V4RZBNMPg+FW0jRz0cafp0bFcJMC28uVwA1s
OM6+gRNIS6+Pp1wdzX0/5Anbg991XZGKsu9cOucFj80no/H98LU8YCh2Ove7xrWm
NifUel5sktz5IM7bhGdp+MCCWZiNXVCBfpAGdWGe7OSHWDzn7YzY2kUkgOU+LSo6
6h8p47zdlLK82FgX4j+ZuMRnNUT1JPPQV2i1ka+y90ocFXwbRCvZhEyFt4fZvhDG
Jhy66fCtbU2O0qkt/Ow8v67OHRfG1NhgMz92YXVm9r54tkeszkpDRBRWv4GSEIJJ
wdo=
-----END CERTIFICATE-----
`

// HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 is the hex
// SHA256 fingerprint for PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644.
const HexHashPEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 = "f72ccd4b250e9e53ebf1d8d400322c21456afb255be1a23d8053eaa8763d3c80"
