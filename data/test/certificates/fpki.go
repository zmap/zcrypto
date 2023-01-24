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

// HexSPKISubjectFingerprintFederalBridgeCA is the hex of the SPKI Subject
// Fingerprint for the Federal Bridge CA.
const HexSPKISubjectFingerprintFederalBridgeCA = "3d12afc9ed8e531eac28d6ac979b629a2472a585bd18fcfddb0084f1997fa362"

// HexSPKISubjectFingerprintFederalBridgeCA2013 is the hex of the SPKI Subject
// Fingerprint of the Federal Bridge CA 2013.
const HexSPKISubjectFingerprintFederalBridgeCA2013 = "219718a39232361f3e20d793a57d73897c59baecfd1c358aedcab87b5ab396d8"

// HexSPKISubjectFingerprintFederalBridgeCA2016 is the hex of the SPKI Subject
// Fingerprint of the Federal Bridge CA 2016.
const HexSPKISubjectFingerprintFederalBridgeCA2016 = "d02e526c39cc5919006349e57a3f42bccffec8d422964edba1ebdbb43b06a1ce"

// HexSPKISubjectFingerprintFederalCommonPolicyCA is the hex of the SPKI Subject
// Fingerprint of the Federal Common Policy CA.
const HexSPKISubjectFingerprintFederalCommonPolicyCA = "be701d4acacaba917b5b936a8aa40e1970827df3b95a70b3c1fe99d4fea0b3c5"

// PEMDoDRootCA3SignedBySelf is the "DoD Root CA 3" self-signed certificate.
const PEMDoDRootCA3SignedBySelf = `
Certificate:
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

// HexHashDoDRootCA3SignedBySelf is the hex SHA256 fingerprint of
// DoDRootCA3SignedBySelf.
const HexHashDoDRootCA3SignedBySelf = "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2"

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

// HexHashDoDRootCA3SignedByDoDInteropCA2Serial655 is the hex SHA256
// fingerprint of DoDRootCA3SignedByDoDInteropCA2Serial655.
const HexHashDoDRootCA3SignedByDoDInteropCA2Serial655 = "fc326b6b92fd2a3dd0c2961428672bf10f974552319f6930c62c6c791d18e84a"

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

// HexHashDoDRootCA3SignedByDoDInteropCA2Serial748 is the hex SHA256
// fingerprint of DoDRootCA3SignedByDoDInteropCA2Serial748.
const HexHashDoDRootCA3SignedByDoDInteropCA2Serial748 = "42e59ccbf68c413a10dd1bb6bc41a930bf1228e16905d9301559cfc4083d589b"

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

// HexHashDoDRootCA3SignedByCCEBInteropRootCA2 is the hex SHA256 fingerprint
// ofDoDRootCA3SignedByCCEBInteropRootCA2.
const HexHashDoDRootCA3SignedByCCEBInteropRootCA2 = "925820ceae31ca372175d0eda58063e0bf8d7f6bd1a6de007d22861bb6270b62"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA2016 is the hex SHA256 fingerprint
// of DoDInteropCA2SignedByFederalBridgeCA2016.
const HexHashDoDInteropCA2SignedByFederalBridgeCA2016 = "4859a804b9e7e62cbdf1fe18c80bd7df77f0b07f716305efce6e5663358f5738"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA is the hex SHA256 fingerprint
// ofDoDInteropCA2SignedByFederalBridgeCA.
const HexHashDoDInteropCA2SignedByFederalBridgeCA = "76eb46d3a0808c7ef85fcd7128c2611e840c8299b836cc88d372564e1be1e96f"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial906 is the hex SHA256
// fingerprint ofDoDInteropCA2SignedByFederalBridgeCA2013Serial906.
const HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial906 = "f1ca80e8c4420f0cab6c2f8b04b4deda19b1cea1f6869e16907674209035d5a1"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 is the hex
// SHA256 fingerprint ofDoDInteropCA2SignedByFederalBridgeCA2013Serial8225.
const HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial8225 = "15fc3efd4294832257ba5a24a232fee2244880dcdc297a2872a6b75727557b1f"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 is the hex
// SHA256 fingerprint ofDoDInteropCA2SignedByFederalBridgeCA2013Serial8844.
const HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial8844 = "ce1a4657b4649ba5701126c740642a56c464225eec3bf398a1a45b57e33356b6"

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

// HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 is the hex
// SHA256 fingerprint forDoDInteropCA2SignedByFederalBridgeCA2013Serial9644.
const HexHashDoDInteropCA2SignedByFederalBridgeCA2013Serial9644 = "f72ccd4b250e9e53ebf1d8d400322c21456afb255be1a23d8053eaa8763d3c80"

// PEMFederalBridgeCASignedByDoDInteropCA2 is the certificate for the Federal
// Bridge CA signed by the DoD Interoperability Root CA 2.
const PEMFederalBridgeCASignedByDoDInteropCA2 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 140 (0x8c)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Validity
            Not Before: Jul 17 14:01:43 2013 GMT
            Not After : Jul 17 14:01:43 2016 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:b9:33:6e:9e:e1:55:12:96:26:f6:6e:b6:85:58:
                    a6:21:69:4b:37:41:24:7d:27:0b:90:40:76:50:4e:
                    6b:a1:4c:e4:12:70:f3:bb:83:f2:40:74:db:d3:17:
                    29:8e:20:79:d7:ae:29:e4:3e:63:86:f9:8c:aa:c5:
                    04:1e:98:d7:48:ab:7c:a2:e4:00:14:b7:e2:3a:54:
                    e8:6c:7d:23:61:65:36:49:b1:22:a8:36:c6:7b:d9:
                    3c:6a:39:59:0b:32:f2:96:37:26:71:bd:c6:4a:dd:
                    b1:b5:c3:1e:5e:12:bb:4a:aa:54:4c:8d:3a:2f:c4:
                    65:f0:56:4b:41:e3:f2:7e:8a:ef:7b:e5:22:31:4f:
                    59:88:68:db:0d:5a:dc:90:39:41:77:4f:83:fb:2b:
                    cf:ee:d5:5c:0f:99:9d:92:8c:c3:58:8c:a9:c5:41:
                    4e:c4:d1:57:e8:d4:e1:06:59:4a:d1:d0:aa:d2:05:
                    44:f6:56:ee:8f:4a:3d:8e:c2:41:ab:e5:ea:7a:ae:
                    bf:b6:be:36:e8:1e:95:86:eb:8a:8e:a0:14:07:c8:
                    6c:1d:ee:ee:9f:ff:64:cf:92:80:f9:38:ea:86:74:
                    a3:83:e1:bc:a2:7f:08:b8:2f:96:ab:6a:eb:27:c5:
                    8f:98:cb:b8:cc:33:e8:9f:1b:5a:8a:0c:68:2e:a4:
                    c2:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78

            X509v3 Subject Key Identifier:
                C4:9D:FC:9D:5D:3A:5D:05:7A:BF:02:81:EC:DB:49:70:15:C7:B2:72
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.42
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20

            X509v3 Policy Mappings:
                2.16.840.1.101.2.1.11.36:2.16.840.1.101.3.2.1.3.38, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.4
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Name Constraints: critical
                Excluded:
                  DirName: C = US, O = U.S. Government, OU = DoD

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca.p7c

    Signature Algorithm: sha256WithRSAEncryption
        2f:67:3e:c3:5e:21:4e:c2:cf:c5:a1:76:3b:c3:1e:cc:e5:32:
        fe:1f:9d:a8:9b:2f:0d:af:2b:e1:61:ef:d4:5b:0e:d5:05:d7:
        a8:b8:14:b8:a3:8d:f1:7b:c8:c5:c3:0b:6c:14:c8:87:43:d4:
        89:2c:ac:d0:8c:e2:8c:a8:62:d2:05:d5:e6:a4:99:82:00:3e:
        e0:aa:47:e7:7d:a8:58:69:e5:ac:85:fa:bc:fa:65:3b:8b:93:
        eb:bb:23:57:9d:41:e7:2b:d1:0d:5c:21:c4:a0:76:5c:15:99:
        3a:a3:9e:77:fa:0e:98:f2:54:11:fc:74:be:7f:c9:d1:17:f7:
        9e:ae:55:26:51:8a:1b:c6:84:00:b3:f2:32:8f:e4:37:0f:96:
        cf:f6:2a:c1:cd:b8:71:63:ed:4f:4c:70:ef:88:d1:18:67:e2:
        39:f0:34:60:a9:60:ff:37:9c:21:b9:1b:d1:2c:ba:59:43:7c:
        d2:56:ac:13:33:13:6e:b6:b3:3d:c8:89:3f:43:2a:31:5f:9f:
        a8:65:2e:e8:dc:33:e3:6f:dd:3b:d0:7e:c4:27:87:ae:50:a5:
        8a:41:00:86:9e:91:bb:f9:85:fe:2b:83:a4:da:7a:73:34:0f:
        7d:bf:a9:39:d9:03:91:0e:b4:72:16:da:67:43:02:fe:16:f3:
        b8:43:e4:eb
-----BEGIN CERTIFICATE-----
MIIFtDCCBJygAwIBAgICAIwwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQL
EwNQS0kxJzAlBgNVBAMTHkRvRCBJbnRlcm9wZXJhYmlsaXR5IFJvb3QgQ0EgMjAe
Fw0xMzA3MTcxNDAxNDNaFw0xNjA3MTcxNDAxNDNaMFIxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxGjAYBgNVBAMT
EUZlZGVyYWwgQnJpZGdlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAuTNunuFVEpYm9m62hVimIWlLN0EkfScLkEB2UE5roUzkEnDzu4PyQHTb0xcp
jiB5164p5D5jhvmMqsUEHpjXSKt8ouQAFLfiOlTobH0jYWU2SbEiqDbGe9k8ajlZ
CzLyljcmcb3GSt2xtcMeXhK7SqpUTI06L8Rl8FZLQePyforve+UiMU9ZiGjbDVrc
kDlBd0+D+yvP7tVcD5mdkozDWIypxUFOxNFX6NThBllK0dCq0gVE9lbuj0o9jsJB
q+Xqeq6/tr426B6VhuuKjqAUB8hsHe7un/9kz5KA+TjqhnSjg+G8on8IuC+Wq2rr
J8WPmMu4zDPonxtaigxoLqTCYwIDAQABo4ICeDCCAnQwHwYDVR0jBBgwFoAU//iu
E4uSK3mSQaN2XCyBnprFnHgwHQYDVR0OBBYEFMSd/J1dOl0Fer8CgezbSXAVx7Jy
MA4GA1UdDwEB/wQEAwIBBjBpBgNVHSAEYjBgMAsGCWCGSAFlAgELJDALBglghkgB
ZQIBCyowDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwGCmCGSAFlAwIBAxIw
DAYKYIZIAWUDAgEDEzAMBgpghkgBZQMCAQMUMFQGA1UdIQRNMEswFwYJYIZIAWUC
AQskBgpghkgBZQMCAQMmMBcGCWCGSAFlAgELKgYKYIZIAWUDAgEDDDAXBglghkgB
ZQIBCyoGCmCGSAFlAwIBAwQwDwYDVR0TAQH/BAUwAwEB/zBJBgNVHR4BAf8EPzA9
oTswOaQ3MDUxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQx
DDAKBgNVBAsTA0RvRDAPBgNVHSQBAf8EBTADgAEAMEcGA1UdHwRAMD4wPKA6oDiG
Nmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElOVEVST1BFUkFCSUxJVFlST09U
Q0EyLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly9jcmwu
ZGlzYS5taWwvaXNzdWVkdG8vRE9ESU5URVJPUEVSQUJJTElUWVJPT1RDQTJfSVQu
cDdjME8GCCsGAQUFBwELBEMwQTA/BggrBgEFBQcwBYYzaHR0cDovL2h0dHAuZnBr
aS5nb3YvYnJpZGdlL2NhQ2VydHNJc3N1ZWRCeWZiY2EucDdjMA0GCSqGSIb3DQEB
CwUAA4IBAQAvZz7DXiFOws/FoXY7wx7M5TL+H52omy8NryvhYe/UWw7VBdeouBS4
o43xe8jFwwtsFMiHQ9SJLKzQjOKMqGLSBdXmpJmCAD7gqkfnfahYaeWshfq8+mU7
i5PruyNXnUHnK9ENXCHEoHZcFZk6o553+g6Y8lQR/HS+f8nRF/eerlUmUYobxoQA
s/Iyj+Q3D5bP9irBzbhxY+1PTHDviNEYZ+I58DRgqWD/N5whuRvRLLpZQ3zSVqwT
MxNutrM9yIk/QyoxX5+oZS7o3DPjb9070H7EJ4euUKWKQQCGnpG7+YX+K4Ok2npz
NA99v6k52QORDrRyFtpnQwL+FvO4Q+Tr
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCASignedByDoDInteropCA2 is the hex SHA256 fingerprint
// ofFederalBridgeCASignedByDoDInteropCA2.
const HexHashFederalBridgeCASignedByDoDInteropCA2 = "fa22bf37e4111e66c0c0761eae45adc973a88a87a47b7d8f65b485d563fa5c2b"

// PEMFederalBridgeCASignedByFederalBridgeCA2013 is the certificate for the Federal
// Bridge CA signed by the Federal Bridge CA 2013.
const PEMFederalBridgeCASignedByFederalBridgeCA2013 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 6 (0x6)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Validity
            Not Before: Oct 21 19:28:34 2013 GMT
            Not After : Oct 11 05:25:13 2016 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:b9:33:6e:9e:e1:55:12:96:26:f6:6e:b6:85:58:
                    a6:21:69:4b:37:41:24:7d:27:0b:90:40:76:50:4e:
                    6b:a1:4c:e4:12:70:f3:bb:83:f2:40:74:db:d3:17:
                    29:8e:20:79:d7:ae:29:e4:3e:63:86:f9:8c:aa:c5:
                    04:1e:98:d7:48:ab:7c:a2:e4:00:14:b7:e2:3a:54:
                    e8:6c:7d:23:61:65:36:49:b1:22:a8:36:c6:7b:d9:
                    3c:6a:39:59:0b:32:f2:96:37:26:71:bd:c6:4a:dd:
                    b1:b5:c3:1e:5e:12:bb:4a:aa:54:4c:8d:3a:2f:c4:
                    65:f0:56:4b:41:e3:f2:7e:8a:ef:7b:e5:22:31:4f:
                    59:88:68:db:0d:5a:dc:90:39:41:77:4f:83:fb:2b:
                    cf:ee:d5:5c:0f:99:9d:92:8c:c3:58:8c:a9:c5:41:
                    4e:c4:d1:57:e8:d4:e1:06:59:4a:d1:d0:aa:d2:05:
                    44:f6:56:ee:8f:4a:3d:8e:c2:41:ab:e5:ea:7a:ae:
                    bf:b6:be:36:e8:1e:95:86:eb:8a:8e:a0:14:07:c8:
                    6c:1d:ee:ee:9f:ff:64:cf:92:80:f9:38:ea:86:74:
                    a3:83:e1:bc:a2:7f:08:b8:2f:96:ab:6a:eb:27:c5:
                    8f:98:cb:b8:cc:33:e8:9f:1b:5a:8a:0c:68:2e:a4:
                    c2:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2013.p7c

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca.p7c

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2013.crl

            X509v3 Subject Key Identifier:
                C4:9D:FC:9D:5D:3A:5D:05:7A:BF:02:81:EC:DB:49:70:15:C7:B2:72
    Signature Algorithm: sha256WithRSAEncryption
        4c:c2:92:36:81:b2:ae:46:74:bc:cf:a9:87:37:34:4d:88:76:
        c8:85:9d:51:ef:45:2b:a8:c2:88:50:67:79:48:17:72:f7:8c:
        61:a0:4a:ba:1a:30:89:15:9d:66:64:87:1d:42:d2:1d:40:6f:
        1c:44:58:84:06:f3:37:59:95:a3:8f:99:95:91:93:4a:8f:40:
        86:23:26:49:03:63:c6:d8:9f:ef:5d:11:02:4f:55:12:c3:c7:
        b9:72:c5:23:65:d6:86:71:21:8b:9e:48:1a:cf:0d:d4:6e:df:
        f4:c3:8c:e0:db:a6:6e:e5:e9:91:0c:23:99:f7:3c:a0:77:75:
        6e:5f:9d:e4:f8:1c:9a:eb:b7:f0:d9:24:ab:9b:b5:cc:84:dd:
        e8:87:ea:53:9a:aa:d2:25:0f:11:74:39:01:be:03:dc:6d:ef:
        e8:e4:35:94:8b:c7:74:1d:77:38:3a:2e:92:50:ad:bd:ee:45:
        d8:e3:f8:bf:50:14:1d:6e:25:48:84:38:9e:65:d8:28:bb:72:
        1c:8e:8a:11:12:60:f7:22:b9:09:a1:43:01:cd:5f:22:5b:0c:
        52:e1:6a:f8:ba:17:60:8b:81:e0:4d:24:03:ce:f0:6d:7a:0c:
        42:92:99:e3:86:7e:d9:4e:cb:51:e4:c3:7e:5f:dc:55:e1:39:
        83:71:8d:48
-----BEGIN CERTIFICATE-----
MIIEbDCCA1SgAwIBAgIBBjANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQ0wCwYDVQQLEwRGUEtJMR8wHQYDVQQD
ExZGZWRlcmFsIEJyaWRnZSBDQSAyMDEzMB4XDTEzMTAyMTE5MjgzNFoXDTE2MTAx
MTA1MjUxM1owUjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
dDENMAsGA1UECxMERlBLSTEaMBgGA1UEAxMRRmVkZXJhbCBCcmlkZ2UgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5M26e4VUSlib2braFWKYhaUs3
QSR9JwuQQHZQTmuhTOQScPO7g/JAdNvTFymOIHnXrinkPmOG+YyqxQQemNdIq3yi
5AAUt+I6VOhsfSNhZTZJsSKoNsZ72TxqOVkLMvKWNyZxvcZK3bG1wx5eErtKqlRM
jTovxGXwVktB4/J+iu975SIxT1mIaNsNWtyQOUF3T4P7K8/u1VwPmZ2SjMNYjKnF
QU7E0Vfo1OEGWUrR0KrSBUT2Vu6PSj2OwkGr5ep6rr+2vjboHpWG64qOoBQHyGwd
7u6f/2TPkoD5OOqGdKOD4byifwi4L5arausnxY+Yy7jMM+ifG1qKDGgupMJjAgMB
AAGjggFGMIIBQjAPBgNVHRMBAf8EBTADAQH/MFMGCCsGAQUFBwEBBEcwRTBDBggr
BgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2NhQ2VydHNJc3N1
ZWRUb2ZiY2EyMDEzLnA3YzBPBggrBgEFBQcBCwRDMEEwPwYIKwYBBQUHMAWGM2h0
dHA6Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9jYUNlcnRzSXNzdWVkQnlmYmNhLnA3
YzAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUu850cYM0TlkyRRVfQGBg3Cuw
tOQwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdl
L2ZiY2EyMDEzLmNybDAdBgNVHQ4EFgQUxJ38nV06XQV6vwKB7NtJcBXHsnIwDQYJ
KoZIhvcNAQELBQADggEBAEzCkjaBsq5GdLzPqYc3NE2IdsiFnVHvRSuowohQZ3lI
F3L3jGGgSroaMIkVnWZkhx1C0h1AbxxEWIQG8zdZlaOPmZWRk0qPQIYjJkkDY8bY
n+9dEQJPVRLDx7lyxSNl1oZxIYueSBrPDdRu3/TDjODbpm7l6ZEMI5n3PKB3dW5f
neT4HJrrt/DZJKubtcyE3eiH6lOaqtIlDxF0OQG+A9xt7+jkNZSLx3Qddzg6LpJQ
rb3uRdjj+L9QFB1uJUiEOJ5l2Ci7chyOihESYPciuQmhQwHNXyJbDFLhavi6F2CL
geBNJAPO8G16DEKSmeOGftlOy1Hkw35f3FXhOYNxjUg=
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCASignedByFederalBridgeCA2013 is the hex SHA256
// fingerprint ofFederalBridgeCASignedByFederalBridgeCA2013.
const HexHashFederalBridgeCASignedByFederalBridgeCA2013 = "687cae341a976f2862ce9c7543f5bbbc466a6cb9719cad755b14b76bc1e7788b"

// PEMFederalBridgeCASignedByFederalCommonPolicyCA is the certificate for the
// Federal Bridge CA signed by the Federal Common Policy CA.
const PEMFederalBridgeCASignedByFederalCommonPolicyCA = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2004 (0x7d4)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Validity
            Not Before: Dec 29 19:28:58 2011 GMT
            Not After : Dec 29 19:27:54 2014 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:b9:33:6e:9e:e1:55:12:96:26:f6:6e:b6:85:58:
                    a6:21:69:4b:37:41:24:7d:27:0b:90:40:76:50:4e:
                    6b:a1:4c:e4:12:70:f3:bb:83:f2:40:74:db:d3:17:
                    29:8e:20:79:d7:ae:29:e4:3e:63:86:f9:8c:aa:c5:
                    04:1e:98:d7:48:ab:7c:a2:e4:00:14:b7:e2:3a:54:
                    e8:6c:7d:23:61:65:36:49:b1:22:a8:36:c6:7b:d9:
                    3c:6a:39:59:0b:32:f2:96:37:26:71:bd:c6:4a:dd:
                    b1:b5:c3:1e:5e:12:bb:4a:aa:54:4c:8d:3a:2f:c4:
                    65:f0:56:4b:41:e3:f2:7e:8a:ef:7b:e5:22:31:4f:
                    59:88:68:db:0d:5a:dc:90:39:41:77:4f:83:fb:2b:
                    cf:ee:d5:5c:0f:99:9d:92:8c:c3:58:8c:a9:c5:41:
                    4e:c4:d1:57:e8:d4:e1:06:59:4a:d1:d0:aa:d2:05:
                    44:f6:56:ee:8f:4a:3d:8e:c2:41:ab:e5:ea:7a:ae:
                    bf:b6:be:36:e8:1e:95:86:eb:8a:8e:a0:14:07:c8:
                    6c:1d:ee:ee:9f:ff:64:cf:92:80:f9:38:ea:86:74:
                    a3:83:e1:bc:a2:7f:08:b8:2f:96:ab:6a:eb:27:c5:
                    8f:98:cb:b8:cc:33:e8:9f:1b:5a:8a:0c:68:2e:a4:
                    c2:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.6
                Policy: 2.16.840.1.101.3.2.1.3.7
                Policy: 2.16.840.1.101.3.2.1.3.8
                Policy: 2.16.840.1.101.3.2.1.3.16
                Policy: 2.16.840.1.101.3.2.1.3.36
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.21
                Policy: 2.16.840.1.101.3.2.1.3.23
                Policy: 2.16.840.1.101.3.2.1.3.22
                Policy: 2.16.840.1.101.3.2.1.3.24
                Policy: 2.16.840.1.101.3.2.1.3.25
                Policy: 2.16.840.1.101.3.2.1.3.26
                Policy: 2.16.840.1.101.3.2.1.3.27

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/fcpca/caCertsIssuedTofcpca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.3.7:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.3.2.1.3.16:2.16.840.1.101.3.2.1.3.4, 2.16.840.1.101.3.2.1.3.8:2.16.840.1.101.3.2.1.3.37, 2.16.840.1.101.3.2.1.3.36:2.16.840.1.101.3.2.1.3.38
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca.p7c

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/fcpca/fcpca.crl

            X509v3 Subject Key Identifier:
                C4:9D:FC:9D:5D:3A:5D:05:7A:BF:02:81:EC:DB:49:70:15:C7:B2:72
    Signature Algorithm: sha256WithRSAEncryption
        73:86:2a:f3:5b:fb:e2:d5:c1:47:41:b5:11:a8:50:11:63:11:
        08:67:a5:64:23:b3:30:07:66:e5:be:61:ff:35:89:7e:5d:87:
        c3:75:25:d8:63:99:ab:8f:30:50:a9:87:70:ae:8b:8f:ea:26:
        ac:3b:bd:47:84:a0:86:85:6c:89:ca:b3:a5:04:cd:eb:16:b6:
        b9:de:bc:6c:b0:27:8a:d0:c4:b0:5c:a5:27:8c:c5:5d:ff:e3:
        e8:eb:e8:fb:37:78:82:19:47:98:0f:25:dc:a7:b3:bd:a4:33:
        56:86:cf:75:c7:ae:9a:2b:ac:ca:22:d5:a9:38:79:f5:c6:2c:
        4b:69:73:a4:8a:d7:9f:2c:17:dc:33:92:77:d0:95:48:7b:c2:
        6f:3d:6f:64:eb:42:d5:eb:1d:39:2d:5d:46:22:15:36:9c:cb:
        0f:ff:a9:2f:7a:63:b5:3e:cc:45:a3:df:22:15:06:c4:90:07:
        7d:fc:9d:2d:e8:e1:12:09:30:9c:66:84:61:61:b4:98:63:da:
        83:c6:a7:e0:f1:a7:c2:ba:88:2a:29:55:52:32:08:3b:2a:77:
        30:f4:74:06:c3:d2:d8:64:e1:08:33:33:65:1e:02:2c:d1:5e:
        fc:6c:44:a8:de:87:19:1b:6f:07:d7:67:cd:11:62:70:9b:c8:
        cf:f9:fa:a4
-----BEGIN CERTIFICATE-----
MIIGLjCCBRagAwIBAgICB9QwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTExMTIyOTE5Mjg1OFoXDTE0
MTIyOTE5Mjc1NFowUjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDENMAsGA1UECxMERlBLSTEaMBgGA1UEAxMRRmVkZXJhbCBCcmlkZ2UgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5M26e4VUSlib2braFWKYh
aUs3QSR9JwuQQHZQTmuhTOQScPO7g/JAdNvTFymOIHnXrinkPmOG+YyqxQQemNdI
q3yi5AAUt+I6VOhsfSNhZTZJsSKoNsZ72TxqOVkLMvKWNyZxvcZK3bG1wx5eErtK
qlRMjTovxGXwVktB4/J+iu975SIxT1mIaNsNWtyQOUF3T4P7K8/u1VwPmZ2SjMNY
jKnFQU7E0Vfo1OEGWUrR0KrSBUT2Vu6PSj2OwkGr5ep6rr+2vjboHpWG64qOoBQH
yGwd7u6f/2TPkoD5OOqGdKOD4byifwi4L5arausnxY+Yy7jMM+ifG1qKDGgupMJj
AgMBAAGjggMFMIIDATAPBgNVHRMBAf8EBTADAQH/MIIBMwYDVR0gBIIBKjCCASYw
DAYKYIZIAWUDAgEDAjAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAwEwDAYKYIZI
AWUDAgEDBjAMBgpghkgBZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgED
EDAMBgpghkgBZQMCAQMkMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDDjAMBgpg
hkgBZQMCAQMPMAwGCmCGSAFlAwIBAxIwDAYKYIZIAWUDAgEDFDAMBgpghkgBZQMC
AQMTMAwGCmCGSAFlAwIBAxUwDAYKYIZIAWUDAgEDFzAMBgpghkgBZQMCAQMWMAwG
CmCGSAFlAwIBAxgwDAYKYIZIAWUDAgEDGTAMBgpghkgBZQMCAQMaMAwGCmCGSAFl
AwIBAxswTwYIKwYBBQUHAQEEQzBBMD8GCCsGAQUFBzAChjNodHRwOi8vaHR0cC5m
cGtpLmdvdi9mY3BjYS9jYUNlcnRzSXNzdWVkVG9mY3BjYS5wN2MwgY0GA1UdIQSB
hTCBgjAYBgpghkgBZQMCAQMGBgpghkgBZQMCAQMDMBgGCmCGSAFlAwIBAwcGCmCG
SAFlAwIBAwwwGAYKYIZIAWUDAgEDEAYKYIZIAWUDAgEDBDAYBgpghkgBZQMCAQMI
BgpghkgBZQMCAQMlMBgGCmCGSAFlAwIBAyQGCmCGSAFlAwIBAyYwTwYIKwYBBQUH
AQsEQzBBMD8GCCsGAQUFBzAFhjNodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2Uv
Y2FDZXJ0c0lzc3VlZEJ5ZmJjYS5wN2MwDgYDVR0PAQH/BAQDAgEGMB8GA1UdIwQY
MBaAFK0MenVc5fOYxHmYDqwo/Zf05wL8MDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6
Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2ZjcGNhLmNybDAdBgNVHQ4EFgQUxJ38nV06
XQV6vwKB7NtJcBXHsnIwDQYJKoZIhvcNAQELBQADggEBAHOGKvNb++LVwUdBtRGo
UBFjEQhnpWQjszAHZuW+Yf81iX5dh8N1JdhjmauPMFCph3Cui4/qJqw7vUeEoIaF
bInKs6UEzesWtrnevGywJ4rQxLBcpSeMxV3/4+jr6Ps3eIIZR5gPJdyns72kM1aG
z3XHrporrMoi1ak4efXGLEtpc6SK158sF9wzknfQlUh7wm89b2TrQtXrHTktXUYi
FTacyw//qS96Y7U+zEWj3yIVBsSQB338nS3o4RIJMJxmhGFhtJhj2oPGp+Dxp8K6
iCopVVIyCDsqdzD0dAbD0thk4QgzM2UeAizRXvxsRKjehxkbbwfXZ80RYnCbyM/5
+qQ=
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCASignedByFederalCommonPolicyCA is the hex SHA256
// fingeprint ofFederalBridgeCASignedByFederalCommonPolicyCA.
const HexHashFederalBridgeCASignedByFederalCommonPolicyCA = "8a51e575c2eac47ad7d9739684e9bbabcc28caff53bc6a1ebb860a2bdcf732c8"

// PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524 is the certificate for
// the Federal Bridge CA 2013 signed by the Federal Common Policy CA with serial
// numbewr 5524.
const PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 5524 (0x1594)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Validity
            Not Before: Oct 21 17:12:58 2013 GMT
            Not After : Oct 21 17:12:58 2016 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:e8:17:25:c2:59:ef:34:a5:c5:44:3b:00:35:
                    ec:31:40:a5:7a:02:d2:3e:19:14:9b:25:89:cd:4a:
                    8c:3b:e6:5e:6a:da:1c:6b:dd:0c:03:2a:45:84:29:
                    9d:4f:2e:ff:b0:a0:6c:02:c6:5a:a7:78:67:a5:77:
                    bb:c6:98:f8:b1:7e:e2:94:bb:fa:11:4f:63:38:1c:
                    1e:7c:08:0c:9e:f6:2a:15:63:22:62:14:12:e7:9f:
                    d4:ea:50:2e:d4:7e:3e:64:25:e4:2e:1c:1b:b8:ed:
                    5f:65:b4:f3:00:15:4f:0d:24:92:2c:71:50:22:3c:
                    eb:11:69:b3:2c:38:f3:e0:73:a1:98:26:75:a6:2d:
                    56:a9:05:af:9b:c9:38:8c:66:c0:c8:08:3b:43:3c:
                    83:dd:2a:52:ab:08:21:7e:cd:4f:ef:45:69:70:0c:
                    7c:b5:fe:1b:51:4e:09:28:2c:07:2b:4a:79:8c:41:
                    45:c4:53:0b:cd:e5:d4:a6:bb:93:33:d8:37:96:c3:
                    b0:2b:5b:c5:c5:e6:49:5c:41:5b:75:a3:02:db:15:
                    9e:73:d0:a6:cc:e4:c8:9a:1a:c7:01:07:93:b0:df:
                    eb:b8:fd:7f:dc:ab:18:94:92:8b:8d:f4:0c:29:09:
                    50:4f:5b:71:e1:da:50:5e:a3:bf:df:dc:a4:8a:f0:
                    07:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.6
                Policy: 2.16.840.1.101.3.2.1.3.7
                Policy: 2.16.840.1.101.3.2.1.3.8
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.16
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.21
                Policy: 2.16.840.1.101.3.2.1.3.22
                Policy: 2.16.840.1.101.3.2.1.3.23
                Policy: 2.16.840.1.101.3.2.1.3.24
                Policy: 2.16.840.1.101.3.2.1.3.25
                Policy: 2.16.840.1.101.3.2.1.3.26
                Policy: 2.16.840.1.101.3.2.1.3.27
                Policy: 2.16.840.1.101.3.2.1.3.36

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/fcpca/caCertsIssuedTofcpca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.3.7:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.3.2.1.3.16:2.16.840.1.101.3.2.1.3.4, 2.16.840.1.101.3.2.1.3.8:2.16.840.1.101.3.2.1.3.37, 2.16.840.1.101.3.2.1.3.36:2.16.840.1.101.3.2.1.3.38
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2013.p7c

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/fcpca/fcpca.crl

            X509v3 Subject Key Identifier:
                BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4
    Signature Algorithm: sha256WithRSAEncryption
        c7:50:ad:8a:75:35:28:65:8c:18:1c:e7:ed:89:35:17:f9:e3:
        c6:61:94:e2:2b:89:ba:3a:91:19:13:09:36:34:84:8c:f8:b6:
        d5:5c:ad:6b:2a:5b:ff:77:11:2f:6a:e9:be:1c:74:c3:b0:7c:
        35:dc:e8:c7:c4:d9:0b:8a:88:8b:ac:20:fc:96:db:37:d4:38:
        96:5e:c0:b5:12:f1:88:2a:2d:9c:2d:5c:a2:25:59:4e:7b:bb:
        31:c8:6b:5c:7c:57:77:a6:9c:0a:6f:a6:8b:4f:af:6b:b0:51:
        6e:e9:23:b1:bb:6f:06:eb:82:5d:e4:81:cf:63:7e:6d:5c:f1:
        0c:86:cd:d4:f2:50:59:74:39:18:7a:99:1d:a1:7f:31:03:49:
        f7:6d:06:69:6d:b4:6a:49:4d:dc:5c:e7:64:54:59:a2:5b:39:
        27:86:7d:ec:73:71:65:98:60:80:3d:b8:0d:b0:be:61:7b:d2:
        d3:ae:f7:c3:80:72:a7:47:00:2e:98:fb:9c:b6:9f:34:df:99:
        14:b2:c4:80:65:bf:7b:8c:95:9f:b7:89:68:fb:7b:22:2c:c9:
        32:55:75:f1:f0:22:d1:d0:f6:00:44:a9:f6:9c:00:58:d9:18:
        9b:b8:03:ee:b0:e3:f6:3f:8f:a9:53:22:16:2b:d4:e8:16:69:
        52:ea:b3:5a
-----BEGIN CERTIFICATE-----
MIIGNzCCBR+gAwIBAgICFZQwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEzMTAyMTE3MTI1OFoXDTE2
MTAyMTE3MTI1OFowVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0Eg
MjAxMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJzoFyXCWe80pcVE
OwA17DFApXoC0j4ZFJslic1KjDvmXmraHGvdDAMqRYQpnU8u/7CgbALGWqd4Z6V3
u8aY+LF+4pS7+hFPYzgcHnwIDJ72KhVjImIUEuef1OpQLtR+PmQl5C4cG7jtX2W0
8wAVTw0kkixxUCI86xFpsyw48+BzoZgmdaYtVqkFr5vJOIxmwMgIO0M8g90qUqsI
IX7NT+9FaXAMfLX+G1FOCSgsBytKeYxBRcRTC83l1Ka7kzPYN5bDsCtbxcXmSVxB
W3WjAtsVnnPQpszkyJoaxwEHk7Df67j9f9yrGJSSi430DCkJUE9bceHaUF6jv9/c
pIrwB0sCAwEAAaOCAwkwggMFMA8GA1UdEwEB/wQFMAMBAf8wggEzBgNVHSAEggEq
MIIBJjAMBgpghkgBZQMCAQMGMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDCDAM
BgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxAwDAYKYIZIAWUDAgEDATAMBgpghkgB
ZQMCAQMCMAwGCmCGSAFlAwIBAw4wDAYKYIZIAWUDAgEDDzAMBgpghkgBZQMCAQMR
MAwGCmCGSAFlAwIBAxIwDAYKYIZIAWUDAgEDEzAMBgpghkgBZQMCAQMUMAwGCmCG
SAFlAwIBAxUwDAYKYIZIAWUDAgEDFjAMBgpghkgBZQMCAQMXMAwGCmCGSAFlAwIB
AxgwDAYKYIZIAWUDAgEDGTAMBgpghkgBZQMCAQMaMAwGCmCGSAFlAwIBAxswDAYK
YIZIAWUDAgEDJDBPBggrBgEFBQcBAQRDMEEwPwYIKwYBBQUHMAKGM2h0dHA6Ly9o
dHRwLmZwa2kuZ292L2ZjcGNhL2NhQ2VydHNJc3N1ZWRUb2ZjcGNhLnA3YzCBjQYD
VR0hBIGFMIGCMBgGCmCGSAFlAwIBAwYGCmCGSAFlAwIBAwMwGAYKYIZIAWUDAgED
BwYKYIZIAWUDAgEDDDAYBgpghkgBZQMCAQMQBgpghkgBZQMCAQMEMBgGCmCGSAFl
AwIBAwgGCmCGSAFlAwIBAyUwGAYKYIZIAWUDAgEDJAYKYIZIAWUDAgEDJjBTBggr
BgEFBQcBCwRHMEUwQwYIKwYBBQUHMAWGN2h0dHA6Ly9odHRwLmZwa2kuZ292L2Jy
aWRnZS9jYUNlcnRzSXNzdWVkQnlmYmNhMjAxMy5wN2MwDgYDVR0PAQH/BAQDAgEG
MB8GA1UdIwQYMBaAFK0MenVc5fOYxHmYDqwo/Zf05wL8MDUGA1UdHwQuMCwwKqAo
oCaGJGh0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2ZjcGNhLmNybDAdBgNVHQ4E
FgQUu850cYM0TlkyRRVfQGBg3CuwtOQwDQYJKoZIhvcNAQELBQADggEBAMdQrYp1
NShljBgc5+2JNRf548ZhlOIribo6kRkTCTY0hIz4ttVcrWsqW/93ES9q6b4cdMOw
fDXc6MfE2QuKiIusIPyW2zfUOJZewLUS8YgqLZwtXKIlWU57uzHIa1x8V3emnApv
potPr2uwUW7pI7G7bwbrgl3kgc9jfm1c8QyGzdTyUFl0ORh6mR2hfzEDSfdtBmlt
tGpJTdxc52RUWaJbOSeGfexzcWWYYIA9uA2wvmF70tOu98OAcqdHAC6Y+5y2nzTf
mRSyxIBlv3uMlZ+3iWj7eyIsyTJVdfHwItHQ9gBEqfacAFjZGJu4A+6w4/Y/j6lT
IhYr1OgWaVLqs1o=
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2013SignedByCommonPolicyCASerial5524 is the hex
// SHA256 fingerprint ofFederalBridgeCA2013SignedByCommonPolicyCASerial5524.
const HexHashFederalBridgeCA2013SignedByCommonPolicyCASerial5524 = "ae014e287fb3709f7d57c29065cdc0d37499e52f83f5ffbe83b883698a2c03f6"

// PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424 is the certificate
// for the Federal Bridge CA 2013 signed by the Federal Common Policy CA with
// the serial number 11424.
const PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 11424 (0x2ca0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Validity
            Not Before: Jun 24 15:45:07 2015 GMT
            Not After : Jun 24 15:45:07 2018 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:e8:17:25:c2:59:ef:34:a5:c5:44:3b:00:35:
                    ec:31:40:a5:7a:02:d2:3e:19:14:9b:25:89:cd:4a:
                    8c:3b:e6:5e:6a:da:1c:6b:dd:0c:03:2a:45:84:29:
                    9d:4f:2e:ff:b0:a0:6c:02:c6:5a:a7:78:67:a5:77:
                    bb:c6:98:f8:b1:7e:e2:94:bb:fa:11:4f:63:38:1c:
                    1e:7c:08:0c:9e:f6:2a:15:63:22:62:14:12:e7:9f:
                    d4:ea:50:2e:d4:7e:3e:64:25:e4:2e:1c:1b:b8:ed:
                    5f:65:b4:f3:00:15:4f:0d:24:92:2c:71:50:22:3c:
                    eb:11:69:b3:2c:38:f3:e0:73:a1:98:26:75:a6:2d:
                    56:a9:05:af:9b:c9:38:8c:66:c0:c8:08:3b:43:3c:
                    83:dd:2a:52:ab:08:21:7e:cd:4f:ef:45:69:70:0c:
                    7c:b5:fe:1b:51:4e:09:28:2c:07:2b:4a:79:8c:41:
                    45:c4:53:0b:cd:e5:d4:a6:bb:93:33:d8:37:96:c3:
                    b0:2b:5b:c5:c5:e6:49:5c:41:5b:75:a3:02:db:15:
                    9e:73:d0:a6:cc:e4:c8:9a:1a:c7:01:07:93:b0:df:
                    eb:b8:fd:7f:dc:ab:18:94:92:8b:8d:f4:0c:29:09:
                    50:4f:5b:71:e1:da:50:5e:a3:bf:df:dc:a4:8a:f0:
                    07:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/fcpca/caCertsIssuedTofcpca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.3.7:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.3.2.1.3.8:2.16.840.1.101.3.2.1.3.37, 2.16.840.1.101.3.2.1.3.16:2.16.840.1.101.3.2.1.3.4, 2.16.840.1.101.3.2.1.3.36:2.16.840.1.101.3.2.1.3.38
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.38
                Policy: 2.16.840.1.101.3.2.1.3.4
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.6
                Policy: 2.16.840.1.101.3.2.1.3.7
                Policy: 2.16.840.1.101.3.2.1.3.8
                Policy: 2.16.840.1.101.3.2.1.3.36
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.16
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.40
                Policy: 2.16.840.1.101.3.2.1.3.41
                Policy: 2.16.840.1.101.3.2.1.3.39

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2013.p7c

            X509v3 Policy Constraints: critical
                Inhibit Policy Mapping:2
            X509v3 Inhibit Any Policy: critical
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/fcpca/fcpca.crl

            X509v3 Subject Key Identifier:
                BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4
    Signature Algorithm: sha256WithRSAEncryption
        c0:1e:6d:27:f0:79:47:52:46:84:c8:88:5d:2e:9c:a6:76:fd:
        fc:f9:85:d2:79:3c:06:21:fb:cc:fd:27:39:bc:a3:1a:91:64:
        57:a8:5e:80:71:b0:43:66:9d:2a:f8:11:47:ba:0c:7e:58:5f:
        b7:51:8f:23:b9:dd:13:ef:18:f2:89:f4:51:37:59:81:4a:c4:
        70:ad:47:ec:8b:1a:53:71:e7:2f:49:66:c6:ef:84:1b:2c:f3:
        43:5d:3c:11:7b:41:20:5b:8e:5a:72:d5:01:84:f6:32:f5:01:
        f1:3a:c8:7e:8f:f4:fa:d0:c5:78:d6:bf:a3:84:1c:18:66:c8:
        4d:bc:33:fd:df:4d:ce:78:b2:52:1b:46:88:72:67:4d:6d:72:
        5b:bb:e1:57:2d:cf:3e:0a:4d:07:37:70:94:b2:23:bb:da:d5:
        be:6f:87:52:f6:57:53:a8:6b:33:3b:60:d9:b0:84:0e:b0:4a:
        59:4f:6b:ac:b7:4c:95:be:37:b1:d3:39:83:c8:b3:8d:eb:dc:
        38:65:cf:16:33:66:ae:72:92:8f:0d:68:e4:d2:5d:72:73:30:
        08:a5:4c:74:5a:dc:1f:9b:4b:71:60:9c:d3:5e:50:bf:2e:6d:
        ce:b2:5b:e6:c6:ed:c9:7c:8b:01:d1:db:b1:cd:a7:a1:62:6e:
        d4:67:5e:31
-----BEGIN CERTIFICATE-----
MIIGZTCCBU2gAwIBAgICLKAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTE1MDYyNDE1NDUwN1oXDTE4
MDYyNDE1NDUwN1owVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0Eg
MjAxMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJzoFyXCWe80pcVE
OwA17DFApXoC0j4ZFJslic1KjDvmXmraHGvdDAMqRYQpnU8u/7CgbALGWqd4Z6V3
u8aY+LF+4pS7+hFPYzgcHnwIDJ72KhVjImIUEuef1OpQLtR+PmQl5C4cG7jtX2W0
8wAVTw0kkixxUCI86xFpsyw48+BzoZgmdaYtVqkFr5vJOIxmwMgIO0M8g90qUqsI
IX7NT+9FaXAMfLX+G1FOCSgsBytKeYxBRcRTC83l1Ka7kzPYN5bDsCtbxcXmSVxB
W3WjAtsVnnPQpszkyJoaxwEHk7Df67j9f9yrGJSSi430DCkJUE9bceHaUF6jv9/c
pIrwB0sCAwEAAaOCAzcwggMzMA8GA1UdEwEB/wQFMAMBAf8wTwYIKwYBBQUHAQEE
QzBBMD8GCCsGAQUFBzAChjNodHRwOi8vaHR0cC5mcGtpLmdvdi9mY3BjYS9jYUNl
cnRzSXNzdWVkVG9mY3BjYS5wN2MwgY0GA1UdIQSBhTCBgjAYBgpghkgBZQMCAQMG
BgpghkgBZQMCAQMDMBgGCmCGSAFlAwIBAwcGCmCGSAFlAwIBAwwwGAYKYIZIAWUD
AgEDCAYKYIZIAWUDAgEDJTAYBgpghkgBZQMCAQMQBgpghkgBZQMCAQMEMBgGCmCG
SAFlAwIBAyQGCmCGSAFlAwIBAyYwggFBBgNVHSAEggE4MIIBNDAMBgpghkgBZQMC
AQMBMAwGCmCGSAFlAwIBAwIwDAYKYIZIAWUDAgEDAzAMBgpghkgBZQMCAQMMMAwG
CmCGSAFlAwIBAw4wDAYKYIZIAWUDAgEDDzAMBgpghkgBZQMCAQMlMAwGCmCGSAFl
AwIBAyYwDAYKYIZIAWUDAgEDBDAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMw
DAYKYIZIAWUDAgEDFDAMBgpghkgBZQMCAQMGMAwGCmCGSAFlAwIBAwcwDAYKYIZI
AWUDAgEDCDAMBgpghkgBZQMCAQMkMAwGCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgED
EDAMBgpghkgBZQMCAQMRMAwGCmCGSAFlAwIBAygwDAYKYIZIAWUDAgEDKTAMBgpg
hkgBZQMCAQMnMFMGCCsGAQUFBwELBEcwRTBDBggrBgEFBQcwBYY3aHR0cDovL2h0
dHAuZnBraS5nb3YvYnJpZGdlL2NhQ2VydHNJc3N1ZWRCeWZiY2EyMDEzLnA3YzAP
BgNVHSQBAf8EBTADgQECMA0GA1UdNgEB/wQDAgEAMA4GA1UdDwEB/wQEAwIBBjAf
BgNVHSMEGDAWgBStDHp1XOXzmMR5mA6sKP2X9OcC/DA1BgNVHR8ELjAsMCqgKKAm
hiRodHRwOi8vaHR0cC5mcGtpLmdvdi9mY3BjYS9mY3BjYS5jcmwwHQYDVR0OBBYE
FLvOdHGDNE5ZMkUVX0BgYNwrsLTkMA0GCSqGSIb3DQEBCwUAA4IBAQDAHm0n8HlH
UkaEyIhdLpymdv38+YXSeTwGIfvM/Sc5vKMakWRXqF6AcbBDZp0q+BFHugx+WF+3
UY8jud0T7xjyifRRN1mBSsRwrUfsixpTcecvSWbG74QbLPNDXTwRe0EgW45actUB
hPYy9QHxOsh+j/T60MV41r+jhBwYZshNvDP9303OeLJSG0aIcmdNbXJbu+FXLc8+
Ck0HN3CUsiO72tW+b4dS9ldTqGszO2DZsIQOsEpZT2ust0yVvjex0zmDyLON69w4
Zc8WM2aucpKPDWjk0l1yczAIpUx0Wtwfm0txYJzTXlC/Lm3Oslvmxu3JfIsB0dux
zaehYm7UZ14x
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2013SignedByCommonPolicyCASerial11424 is the hex
// SHA256 fingerprint of
// FederalBridgeCA2013SignedByCommonPolicyCASerial11424.
const HexHashFederalBridgeCA2013SignedByCommonPolicyCASerial11424 = "8ed99089806b1005d6a6417c50f182325b670b9d87b17f3fd7aefc360a300e91"

// PEMFederalBridgeCA2013SignedByIdenTrust is the certificate for the Federal
// Bridge CA 2013 signed by IdenTrust ACES CA 1.
const PEMFederalBridgeCA2013SignedByIdenTrust = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7f:00:00:01:00:00:01:4a:f3:fc:79:ab:00:00:00:02
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=IdenTrust, OU=IdenTrust Public Sector, CN=IdenTrust ACES CA 1
        Validity
            Not Before: Jan 16 18:23:37 2015 GMT
            Not After : Jan 14 18:23:37 2018 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:e8:17:25:c2:59:ef:34:a5:c5:44:3b:00:35:
                    ec:31:40:a5:7a:02:d2:3e:19:14:9b:25:89:cd:4a:
                    8c:3b:e6:5e:6a:da:1c:6b:dd:0c:03:2a:45:84:29:
                    9d:4f:2e:ff:b0:a0:6c:02:c6:5a:a7:78:67:a5:77:
                    bb:c6:98:f8:b1:7e:e2:94:bb:fa:11:4f:63:38:1c:
                    1e:7c:08:0c:9e:f6:2a:15:63:22:62:14:12:e7:9f:
                    d4:ea:50:2e:d4:7e:3e:64:25:e4:2e:1c:1b:b8:ed:
                    5f:65:b4:f3:00:15:4f:0d:24:92:2c:71:50:22:3c:
                    eb:11:69:b3:2c:38:f3:e0:73:a1:98:26:75:a6:2d:
                    56:a9:05:af:9b:c9:38:8c:66:c0:c8:08:3b:43:3c:
                    83:dd:2a:52:ab:08:21:7e:cd:4f:ef:45:69:70:0c:
                    7c:b5:fe:1b:51:4e:09:28:2c:07:2b:4a:79:8c:41:
                    45:c4:53:0b:cd:e5:d4:a6:bb:93:33:d8:37:96:c3:
                    b0:2b:5b:c5:c5:e6:49:5c:41:5b:75:a3:02:db:15:
                    9e:73:d0:a6:cc:e4:c8:9a:1a:c7:01:07:93:b0:df:
                    eb:b8:fd:7f:dc:ab:18:94:92:8b:8d:f4:0c:29:09:
                    50:4f:5b:71:e1:da:50:5e:a3:bf:df:dc:a4:8a:f0:
                    07:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Inhibit Any Policy: critical
                0
            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.1.2:2.16.840.1.101.3.2.1.3.2, 2.16.840.1.101.3.2.1.1.3:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.1.5:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.1.6:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.1.7:2.16.840.1.101.3.2.1.3.3
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.1.2
                Policy: 2.16.840.1.101.3.2.1.1.3
                Policy: 2.16.840.1.101.3.2.1.1.5
                Policy: 2.16.840.1.101.3.2.1.1.6
                Policy: 2.16.840.1.101.3.2.1.1.7

            X509v3 Subject Key Identifier:
                BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4
            X509v3 CRL Distribution Points:
                URI:http://crl.identrust.com/acespublicsector1.crl

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2013.p7c

            Authority Information Access:
                CA Issuers - URI:http://apps.identrust.com/roots/acespublicsector1.p7c
                OCSP - URI:https://aces.ocsp.identrust.com

            X509v3 Authority Key Identifier:
                keyid:E6:33:09:63:89:B5:66:1A:4F:D5:B3:CC:0F:AB:FB:B5:0C:C7:F3:47

    Signature Algorithm: sha256WithRSAEncryption
        6c:c3:71:b3:ed:4e:73:c3:b7:16:83:05:81:bb:17:bb:eb:34:
        a3:af:a2:f3:18:8d:3e:65:5b:3c:44:ec:a2:c5:58:ed:1b:6d:
        e9:38:4d:d9:30:b8:bb:57:73:df:3f:64:3c:be:b4:8d:7b:9d:
        13:c7:93:85:b9:86:c2:82:ff:7a:e5:03:12:f0:9a:84:31:06:
        b9:4a:5c:8e:e9:3e:42:d7:35:d0:17:9e:d2:8b:89:bc:cd:84:
        d4:73:e0:ed:0c:b9:c9:1c:9e:56:05:79:af:f2:8e:a1:f5:a0:
        9e:b0:02:75:80:6a:ac:ac:97:9c:5c:76:af:f0:3f:ab:1f:6f:
        7d:cb:ea:78:b3:42:91:8e:19:5e:e0:f8:2d:20:2e:66:3f:7f:
        80:b7:44:88:ab:3a:29:c3:59:c7:5b:d2:9a:18:e3:33:2f:39:
        47:41:db:d3:c7:4e:12:b3:4b:2b:ef:58:c1:d4:3d:11:f1:7b:
        e5:5f:8b:43:c6:92:34:78:1e:f8:42:fe:75:cb:52:89:41:34:
        e0:73:80:12:90:2c:94:2a:26:3e:44:36:72:26:73:c0:5c:c0:
        88:d0:5f:1f:04:de:3f:9a:66:03:56:b3:d8:73:fd:5a:45:19:
        de:99:6b:66:96:43:f3:4a:4a:66:30:32:21:c5:66:45:17:0d:
        ce:5b:7c:63
-----BEGIN CERTIFICATE-----
MIIFrzCCBJegAwIBAgIQfwAAAQAAAUrz/HmrAAAAAjANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MSAwHgYDVQQLExdJZGVu
VHJ1c3QgUHVibGljIFNlY3RvcjEcMBoGA1UEAxMTSWRlblRydXN0IEFDRVMgQ0Eg
MTAeFw0xNTAxMTYxODIzMzdaFw0xODAxMTQxODIzMzdaMFcxCzAJBgNVBAYTAlVT
MRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxHzAdBgNV
BAMTFkZlZGVyYWwgQnJpZGdlIENBIDIwMTMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCc6BclwlnvNKXFRDsANewxQKV6AtI+GRSbJYnNSow75l5q2hxr
3QwDKkWEKZ1PLv+woGwCxlqneGeld7vGmPixfuKUu/oRT2M4HB58CAye9ioVYyJi
FBLnn9TqUC7Ufj5kJeQuHBu47V9ltPMAFU8NJJIscVAiPOsRabMsOPPgc6GYJnWm
LVapBa+byTiMZsDICDtDPIPdKlKrCCF+zU/vRWlwDHy1/htRTgkoLAcrSnmMQUXE
UwvN5dSmu5Mz2DeWw7ArW8XF5klcQVt1owLbFZ5z0KbM5MiaGscBB5Ow3+u4/X/c
qxiUkouN9AwpCVBPW3Hh2lBeo7/f3KSK8AdLAgMBAAGjggJrMIICZzAOBgNVHQ8B
Af8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zANBgNVHTYBAf8EAwIBADCBjQYDVR0h
BIGFMIGCMBgGCmCGSAFlAwIBAQIGCmCGSAFlAwIBAwIwGAYKYIZIAWUDAgEBAwYK
YIZIAWUDAgEDAzAYBgpghkgBZQMCAQEFBgpghkgBZQMCAQMDMBgGCmCGSAFlAwIB
AQYGCmCGSAFlAwIBAwMwGAYKYIZIAWUDAgEBBwYKYIZIAWUDAgEDAzBPBgNVHSAE
SDBGMAwGCmCGSAFlAwIBAQIwDAYKYIZIAWUDAgEBAzAMBgpghkgBZQMCAQEFMAwG
CmCGSAFlAwIBAQYwDAYKYIZIAWUDAgEBBzAdBgNVHQ4EFgQUu850cYM0TlkyRRVf
QGBg3CuwtOQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5pZGVudHJ1c3Qu
Y29tL2FjZXNwdWJsaWNzZWN0b3IxLmNybDBTBggrBgEFBQcBCwRHMEUwQwYIKwYB
BQUHMAWGN2h0dHA6Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9jYUNlcnRzSXNzdWVk
QnlmYmNhMjAxMy5wN2MwfgYIKwYBBQUHAQEEcjBwMEEGCCsGAQUFBzAChjVodHRw
Oi8vYXBwcy5pZGVudHJ1c3QuY29tL3Jvb3RzL2FjZXNwdWJsaWNzZWN0b3IxLnA3
YzArBggrBgEFBQcwAYYfaHR0cHM6Ly9hY2VzLm9jc3AuaWRlbnRydXN0LmNvbTAf
BgNVHSMEGDAWgBTmMwljibVmGk/Vs8wPq/u1DMfzRzANBgkqhkiG9w0BAQsFAAOC
AQEAbMNxs+1Oc8O3FoMFgbsXu+s0o6+i8xiNPmVbPETsosVY7Rtt6ThN2TC4u1dz
3z9kPL60jXudE8eThbmGwoL/euUDEvCahDEGuUpcjuk+Qtc10Bee0ouJvM2E1HPg
7Qy5yRyeVgV5r/KOofWgnrACdYBqrKyXnFx2r/A/qx9vfcvqeLNCkY4ZXuD4LSAu
Zj9/gLdEiKs6KcNZx1vSmhjjMy85R0Hb08dOErNLK+9YwdQ9EfF75V+LQ8aSNHge
+EL+dctSiUE04HOAEpAslComPkQ2ciZzwFzAiNBfHwTeP5pmA1az2HP9WkUZ3plr
ZpZD80pKZjAyIcVmRRcNzlt8Yw==
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2013SignedByIdenTrust is the hex SHA256 fingerprint
// ofFederalBridgeCA2013SignedByIdenTrust.
const HexHashFederalBridgeCA2013SignedByIdenTrust = "a2d96559f2237d3962a5d879e0327f9610097f83fe3e6f4e8d9fa567e88efca4"

// PEMFederalBridgeCA2013SignedByDoDInteropCA2 is the certificate for the
// Federal Bridge CA 2013 signed by the DoD Interoperability Root CA 2.
const PEMFederalBridgeCA2013SignedByDoDInteropCA2 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 302 (0x12e)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Validity
            Not Before: Apr 16 13:41:32 2014 GMT
            Not After : Apr 16 13:41:32 2017 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2013
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:e8:17:25:c2:59:ef:34:a5:c5:44:3b:00:35:
                    ec:31:40:a5:7a:02:d2:3e:19:14:9b:25:89:cd:4a:
                    8c:3b:e6:5e:6a:da:1c:6b:dd:0c:03:2a:45:84:29:
                    9d:4f:2e:ff:b0:a0:6c:02:c6:5a:a7:78:67:a5:77:
                    bb:c6:98:f8:b1:7e:e2:94:bb:fa:11:4f:63:38:1c:
                    1e:7c:08:0c:9e:f6:2a:15:63:22:62:14:12:e7:9f:
                    d4:ea:50:2e:d4:7e:3e:64:25:e4:2e:1c:1b:b8:ed:
                    5f:65:b4:f3:00:15:4f:0d:24:92:2c:71:50:22:3c:
                    eb:11:69:b3:2c:38:f3:e0:73:a1:98:26:75:a6:2d:
                    56:a9:05:af:9b:c9:38:8c:66:c0:c8:08:3b:43:3c:
                    83:dd:2a:52:ab:08:21:7e:cd:4f:ef:45:69:70:0c:
                    7c:b5:fe:1b:51:4e:09:28:2c:07:2b:4a:79:8c:41:
                    45:c4:53:0b:cd:e5:d4:a6:bb:93:33:d8:37:96:c3:
                    b0:2b:5b:c5:c5:e6:49:5c:41:5b:75:a3:02:db:15:
                    9e:73:d0:a6:cc:e4:c8:9a:1a:c7:01:07:93:b0:df:
                    eb:b8:fd:7f:dc:ab:18:94:92:8b:8d:f4:0c:29:09:
                    50:4f:5b:71:e1:da:50:5e:a3:bf:df:dc:a4:8a:f0:
                    07:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78

            X509v3 Subject Key Identifier:
                BB:CE:74:71:83:34:4E:59:32:45:15:5F:40:60:60:DC:2B:B0:B4:E4
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.42
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.39
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20

            X509v3 Policy Mappings:
                2.16.840.1.101.2.1.11.36:2.16.840.1.101.3.2.1.3.38, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.4
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Name Constraints: critical
                Excluded:
                  DirName: C = US, O = U.S. Government, OU = DoD

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2013.p7c

    Signature Algorithm: sha256WithRSAEncryption
        68:6d:52:24:9d:4c:98:71:ca:aa:3c:72:42:69:76:db:93:11:
        28:6c:12:7c:93:cb:89:28:c4:b0:b9:a6:8d:58:8f:16:e2:aa:
        82:a3:d7:cb:55:cf:b7:b8:5a:c6:01:3e:39:e8:19:4e:e5:ce:
        fc:a6:29:a8:f7:72:c0:9c:48:32:a2:dd:d0:e2:c8:a3:ac:1e:
        65:f8:66:79:68:55:ab:7a:02:42:d5:88:57:87:05:a5:60:0c:
        05:d7:0d:ce:eb:e3:25:cf:19:8b:a0:19:ba:48:04:41:14:21:
        c1:c8:f7:16:de:1b:c5:45:c6:e5:26:a2:e2:5e:2d:13:35:2f:
        2a:99:37:8d:7f:0f:dc:ba:97:61:92:af:51:2e:a9:be:de:bd:
        82:1a:c3:f6:27:53:b5:f5:52:8b:70:39:2d:c8:1e:80:36:db:
        49:d2:c8:0b:f9:8b:f4:02:8e:1b:bc:00:88:e5:db:db:2d:59:
        17:b4:8f:b0:0b:10:c7:f8:c7:ed:e2:01:1b:a4:50:69:23:5f:
        6e:94:79:81:1c:28:27:dd:f3:a9:b5:dd:62:c1:80:fe:e9:12:
        31:28:d9:66:47:f5:9a:46:7c:ad:b0:c1:8c:15:9f:b6:51:b5:
        17:34:41:f0:2d:28:0e:a8:94:ca:a2:83:42:2a:d8:dc:b0:fd:
        59:80:09:7d
-----BEGIN CERTIFICATE-----
MIIFyzCCBLOgAwIBAgICAS4wDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQL
EwNQS0kxJzAlBgNVBAMTHkRvRCBJbnRlcm9wZXJhYmlsaXR5IFJvb3QgQ0EgMjAe
Fw0xNDA0MTYxMzQxMzJaFw0xNzA0MTYxMzQxMzJaMFcxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxHzAdBgNVBAMT
FkZlZGVyYWwgQnJpZGdlIENBIDIwMTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCc6BclwlnvNKXFRDsANewxQKV6AtI+GRSbJYnNSow75l5q2hxr3QwD
KkWEKZ1PLv+woGwCxlqneGeld7vGmPixfuKUu/oRT2M4HB58CAye9ioVYyJiFBLn
n9TqUC7Ufj5kJeQuHBu47V9ltPMAFU8NJJIscVAiPOsRabMsOPPgc6GYJnWmLVap
Ba+byTiMZsDICDtDPIPdKlKrCCF+zU/vRWlwDHy1/htRTgkoLAcrSnmMQUXEUwvN
5dSmu5Mz2DeWw7ArW8XF5klcQVt1owLbFZ5z0KbM5MiaGscBB5Ow3+u4/X/cqxiU
kouN9AwpCVBPW3Hh2lBeo7/f3KSK8AdLAgMBAAGjggKKMIIChjAfBgNVHSMEGDAW
gBT/+K4Ti5IreZJBo3ZcLIGemsWceDAdBgNVHQ4EFgQUu850cYM0TlkyRRVfQGBg
3CuwtOQwDgYDVR0PAQH/BAQDAgEGMHcGA1UdIARwMG4wCwYJYIZIAWUCAQskMAsG
CWCGSAFlAgELKjAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUD
AgEDJzAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMwDAYKYIZIAWUDAgEDFDBU
BgNVHSEETTBLMBcGCWCGSAFlAgELJAYKYIZIAWUDAgEDJjAXBglghkgBZQIBCyoG
CmCGSAFlAwIBAwwwFwYJYIZIAWUCAQsqBgpghkgBZQMCAQMEMA8GA1UdEwEB/wQF
MAMBAf8wSQYDVR0eAQH/BD8wPaE7MDmkNzA1MQswCQYDVQQGEwJVUzEYMBYGA1UE
ChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QwDwYDVR0kAQH/BAUwA4AB
ADBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3JsLmRpc2EubWlsL2NybC9ET0RJ
TlRFUk9QRVJBQklMSVRZUk9PVENBMi5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
AQUFBzAChj5odHRwOi8vY3JsLmRpc2EubWlsL2lzc3VlZHRvL0RPRElOVEVST1BF
UkFCSUxJVFlST09UQ0EyX0lULnA3YzBTBggrBgEFBQcBCwRHMEUwQwYIKwYBBQUH
MAWGN2h0dHA6Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9jYUNlcnRzSXNzdWVkQnlm
YmNhMjAxMy5wN2MwDQYJKoZIhvcNAQELBQADggEBAGhtUiSdTJhxyqo8ckJpdtuT
EShsEnyTy4koxLC5po1YjxbiqoKj18tVz7e4WsYBPjnoGU7lzvymKaj3csCcSDKi
3dDiyKOsHmX4ZnloVat6AkLViFeHBaVgDAXXDc7r4yXPGYugGbpIBEEUIcHI9xbe
G8VFxuUmouJeLRM1LyqZN41/D9y6l2GSr1Euqb7evYIaw/YnU7X1UotwOS3IHoA2
20nSyAv5i/QCjhu8AIjl29stWRe0j7ALEMf4x+3iARukUGkjX26UeYEcKCfd86m1
3WLBgP7pEjEo2WZH9ZpGfK2wwYwVn7ZRtRc0QfAtKA6olMqig0Iq2Nyw/VmACX0=
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2013SignedByDoDInteropCA2 is the hex SHA256
// fingerprint ofFederalBridgeCA2013SignedByDoDInteropCA2.
const HexHashFederalBridgeCA2013SignedByDoDInteropCA2 = "d19ee1728a2fbe37342f3b993d6c3f771516dbba190823ab059b2da0b3e44617"

// PEMFederalBridgeCA2016SignedByDodInteropCA2 is the certificate for the
// Federal Bridge CA 2016 signed by the Dod Interoperability Root CA 2.
const PEMFederalBridgeCA2016SignedByDodInteropCA2 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1061 (0x425)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Interoperability Root CA 2
        Validity
            Not Before: May  9 13:14:15 2017 GMT
            Not After : May  9 13:14:15 2020 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2016
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:be:9d:35:79:6f:25:b5:f4:90:83:6e:13:bf:53:
                    50:ca:cd:1c:96:d4:1c:6b:81:f2:8a:9b:0f:46:a7:
                    df:b7:ef:ff:ed:44:59:ce:87:96:6f:5f:57:b1:fe:
                    33:ab:47:c7:85:97:77:3c:8a:0e:14:cd:2f:79:6a:
                    27:14:d2:78:5b:a5:a5:4b:38:3a:b8:df:f6:8b:0b:
                    da:53:11:23:59:9f:a9:62:32:90:f4:1a:4f:05:83:
                    3e:3d:cd:9b:15:7b:90:d8:8b:a1:cd:cc:b8:c0:43:
                    9f:cd:a7:8b:be:23:41:7d:29:33:df:59:7d:40:c0:
                    e3:da:73:c3:af:43:bf:96:58:4a:c2:83:b2:2a:e2:
                    21:7e:93:97:6a:f9:15:69:8c:7e:0c:68:91:3a:f0:
                    b7:2c:81:5a:0a:bd:92:86:b9:84:99:92:98:04:9f:
                    d4:c4:89:c2:91:e1:21:52:48:7e:dd:00:9f:8f:f9:
                    2d:3e:f2:e8:5e:0a:54:cc:4f:82:48:2f:0c:02:5e:
                    07:b6:32:e4:93:29:37:cc:56:77:21:76:66:1a:99:
                    f2:0b:13:e2:c3:f9:3b:e0:98:1c:9c:3f:f5:23:c8:
                    86:2f:8f:cb:e9:bf:5f:1a:e2:68:32:07:bd:bb:b6:
                    37:89:de:b8:70:fd:c8:c9:83:44:2b:18:be:86:77:
                    12:39
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:FF:F8:AE:13:8B:92:2B:79:92:41:A3:76:5C:2C:81:9E:9A:C5:9C:78

            X509v3 Subject Key Identifier:
                23:B0:B3:7D:16:54:D4:02:56:76:EB:3A:BE:A9:6B:2F:43:7B:28:16
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.2.1.11.36
                Policy: 2.16.840.1.101.2.1.11.42
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.39

            X509v3 Policy Mappings:
                2.16.840.1.101.2.1.11.36:2.16.840.1.101.3.2.1.3.38, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.2.1.11.42:2.16.840.1.101.3.2.1.3.4
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Name Constraints: critical
                Excluded:
                  DirName: C = US, O = U.S. Government, OU = DoD
                  DirName: C = US, O = U.S. Government, OU = ECA

            X509v3 Policy Constraints: critical
                Require Explicit Policy:0
            X509v3 CRL Distribution Points:
                URI:http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl

            Authority Information Access:
                CA Issuers - URI:http://crl.disa.mil/issuedto/DODINTEROPERABILITYROOTCA2_IT.p7c
                OCSP - URI:http://ocsp.disa.mil

            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2016.p7c

            X509v3 Inhibit Any Policy:
                0
    Signature Algorithm: sha256WithRSAEncryption
        b7:02:a4:e4:61:66:40:58:e5:6a:bf:78:d2:02:40:b8:c6:53:
        2a:6e:16:26:46:e1:b4:75:ba:48:94:eb:b5:ec:4c:85:b0:3e:
        6f:70:26:af:10:2d:9e:a3:4a:f0:a4:ab:14:e7:7b:c2:7f:01:
        4b:f9:5d:52:18:0e:cd:9b:1d:5c:85:0d:24:54:51:60:1f:c8:
        70:2c:ff:55:5d:c4:93:d1:7a:79:a2:ea:7c:85:40:72:7a:12:
        f8:fa:d5:e3:25:44:41:6b:5a:20:48:b6:f8:59:83:ed:54:7b:
        d7:f5:97:0b:24:d8:99:20:56:78:05:65:87:0f:ab:cd:3b:87:
        00:d7:29:5e:67:71:df:79:32:46:e9:ca:87:62:75:52:0f:26:
        1c:ca:1a:0e:33:13:da:2c:32:1d:6e:fc:11:f4:19:1b:5b:ac:
        bd:9b:26:bc:6a:f3:bd:63:73:8b:f3:66:e7:6b:cb:d8:9b:ae:
        a9:d0:71:a9:ae:0a:c3:6b:ea:fb:0b:29:b1:40:ee:0c:ed:4d:
        99:08:dc:55:79:50:90:26:fb:e3:f1:d6:53:6b:1a:c7:05:15:
        df:29:33:62:55:f9:b0:db:12:ad:a9:a0:ad:a2:c7:7f:de:f9:
        53:5c:90:f5:f0:80:7f:98:a2:7d:e7:63:55:76:cb:33:49:e4:
        86:c1:cb:e9
-----BEGIN CERTIFICATE-----
MIIGNTCCBR2gAwIBAgICBCUwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQL
EwNQS0kxJzAlBgNVBAMTHkRvRCBJbnRlcm9wZXJhYmlsaXR5IFJvb3QgQ0EgMjAe
Fw0xNzA1MDkxMzE0MTVaFw0yMDA1MDkxMzE0MTVaMFcxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxHzAdBgNVBAMT
FkZlZGVyYWwgQnJpZGdlIENBIDIwMTYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC+nTV5byW19JCDbhO/U1DKzRyW1BxrgfKKmw9Gp9+37//tRFnOh5Zv
X1ex/jOrR8eFl3c8ig4UzS95aicU0nhbpaVLODq43/aLC9pTESNZn6liMpD0Gk8F
gz49zZsVe5DYi6HNzLjAQ5/Np4u+I0F9KTPfWX1AwOPac8OvQ7+WWErCg7Iq4iF+
k5dq+RVpjH4MaJE68LcsgVoKvZKGuYSZkpgEn9TEicKR4SFSSH7dAJ+P+S0+8uhe
ClTMT4JILwwCXge2MuSTKTfMVnchdmYamfILE+LD+TvgmBycP/UjyIYvj8vpv18a
4mgyB727tjeJ3rhw/cjJg0QrGL6GdxI5AgMBAAGjggL0MIIC8DAfBgNVHSMEGDAW
gBT/+K4Ti5IreZJBo3ZcLIGemsWceDAdBgNVHQ4EFgQUI7CzfRZU1AJWdus6vqlr
L0N7KBYwDgYDVR0PAQH/BAQDAgEGMHcGA1UdIARwMG4wCwYJYIZIAWUCAQskMAsG
CWCGSAFlAgELKjAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUD
AgEDEjAMBgpghkgBZQMCAQMTMAwGCmCGSAFlAwIBAxQwDAYKYIZIAWUDAgEDJzBU
BgNVHSEETTBLMBcGCWCGSAFlAgELJAYKYIZIAWUDAgEDJjAXBglghkgBZQIBCyoG
CmCGSAFlAwIBAwwwFwYJYIZIAWUCAQsqBgpghkgBZQMCAQMEMA8GA1UdEwEB/wQF
MAMBAf8wgYQGA1UdHgEB/wR6MHihdjA5pDcwNTELMAkGA1UEBhMCVVMxGDAWBgNV
BAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMDmkNzA1MQswCQYDVQQG
EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNFQ0EwDwYD
VR0kAQH/BAUwA4ABADBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3JsLmRpc2Eu
bWlsL2NybC9ET0RJTlRFUk9QRVJBQklMSVRZUk9PVENBMi5jcmwwfAYIKwYBBQUH
AQEEcDBuMEoGCCsGAQUFBzAChj5odHRwOi8vY3JsLmRpc2EubWlsL2lzc3VlZHRv
L0RPRElOVEVST1BFUkFCSUxJVFlST09UQ0EyX0lULnA3YzAgBggrBgEFBQcwAYYU
aHR0cDovL29jc3AuZGlzYS5taWwwUwYIKwYBBQUHAQsERzBFMEMGCCsGAQUFBzAF
hjdodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2UvY2FDZXJ0c0lzc3VlZEJ5ZmJj
YTIwMTYucDdjMAoGA1UdNgQDAgEAMA0GCSqGSIb3DQEBCwUAA4IBAQC3AqTkYWZA
WOVqv3jSAkC4xlMqbhYmRuG0dbpIlOu17EyFsD5vcCavEC2eo0rwpKsU53vCfwFL
+V1SGA7Nmx1chQ0kVFFgH8hwLP9VXcST0Xp5oup8hUByehL4+tXjJURBa1ogSLb4
WYPtVHvX9ZcLJNiZIFZ4BWWHD6vNO4cA1yleZ3HfeTJG6cqHYnVSDyYcyhoOMxPa
LDIdbvwR9BkbW6y9mya8avO9Y3OL82bna8vYm66p0HGprgrDa+r7CymxQO4M7U2Z
CNxVeVCQJvvj8dZTaxrHBRXfKTNiVfmw2xKtqaCtosd/3vlTXJD18IB/mKJ952NV
dsszSeSGwcvp
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2016SignedByDodInteropCA2 is the hex SHA256
// fingerprint ofFederalBridgeCA2016SignedByDodInteropCA2.
const HexHashFederalBridgeCA2016SignedByDodInteropCA2 = "bf6cbf5649bc6eacf8cc906ecb6b23c190bd926e49cafeb23c3ecf4dc5906bbb"

// PEMFederalBridgeCA2016SignedByFederalCommonPolicyCA is the certificate for
// the Federal Bridge CA 2016 signed by the Federal Common Policy CA.
const PEMFederalBridgeCA2016SignedByFederalCommonPolicyCA = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 16194 (0x3f42)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Validity
            Not Before: Nov  8 18:20:38 2016 GMT
            Not After : Nov  8 18:20:38 2019 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2016
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:be:9d:35:79:6f:25:b5:f4:90:83:6e:13:bf:53:
                    50:ca:cd:1c:96:d4:1c:6b:81:f2:8a:9b:0f:46:a7:
                    df:b7:ef:ff:ed:44:59:ce:87:96:6f:5f:57:b1:fe:
                    33:ab:47:c7:85:97:77:3c:8a:0e:14:cd:2f:79:6a:
                    27:14:d2:78:5b:a5:a5:4b:38:3a:b8:df:f6:8b:0b:
                    da:53:11:23:59:9f:a9:62:32:90:f4:1a:4f:05:83:
                    3e:3d:cd:9b:15:7b:90:d8:8b:a1:cd:cc:b8:c0:43:
                    9f:cd:a7:8b:be:23:41:7d:29:33:df:59:7d:40:c0:
                    e3:da:73:c3:af:43:bf:96:58:4a:c2:83:b2:2a:e2:
                    21:7e:93:97:6a:f9:15:69:8c:7e:0c:68:91:3a:f0:
                    b7:2c:81:5a:0a:bd:92:86:b9:84:99:92:98:04:9f:
                    d4:c4:89:c2:91:e1:21:52:48:7e:dd:00:9f:8f:f9:
                    2d:3e:f2:e8:5e:0a:54:cc:4f:82:48:2f:0c:02:5e:
                    07:b6:32:e4:93:29:37:cc:56:77:21:76:66:1a:99:
                    f2:0b:13:e2:c3:f9:3b:e0:98:1c:9c:3f:f5:23:c8:
                    86:2f:8f:cb:e9:bf:5f:1a:e2:68:32:07:bd:bb:b6:
                    37:89:de:b8:70:fd:c8:c9:83:44:2b:18:be:86:77:
                    12:39
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.6
                Policy: 2.16.840.1.101.3.2.1.3.7
                Policy: 2.16.840.1.101.3.2.1.3.8
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.16
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.36
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.4
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.38
                Policy: 2.16.840.1.101.3.2.1.3.39
                Policy: 2.16.840.1.101.3.2.1.3.40
                Policy: 2.16.840.1.101.3.2.1.3.41

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/fcpca/caCertsIssuedTofcpca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.3.3, 2.16.840.1.101.3.2.1.3.16:2.16.840.1.101.3.2.1.3.4, 2.16.840.1.101.3.2.1.3.7:2.16.840.1.101.3.2.1.3.12, 2.16.840.1.101.3.2.1.3.8:2.16.840.1.101.3.2.1.3.37, 2.16.840.1.101.3.2.1.3.36:2.16.840.1.101.3.2.1.3.38
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/bridge/caCertsIssuedByfbca2016.p7c

            X509v3 Policy Constraints: critical
                Inhibit Policy Mapping:2
            X509v3 Inhibit Any Policy: critical
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/fcpca/fcpca.crl

            X509v3 Subject Key Identifier:
                23:B0:B3:7D:16:54:D4:02:56:76:EB:3A:BE:A9:6B:2F:43:7B:28:16
    Signature Algorithm: sha256WithRSAEncryption
        23:ad:f1:65:e7:65:6a:bc:ec:f3:f2:ef:cf:6a:d1:42:8e:42:
        41:0d:ad:f7:c1:47:95:2f:bc:34:ce:ee:fe:97:a4:ec:30:94:
        99:6c:fb:0f:65:7e:ee:a5:80:10:29:fd:a9:49:68:f5:b2:d7:
        5b:be:97:bb:40:b9:71:18:fd:9b:8c:6f:99:5c:25:e2:04:95:
        15:db:e2:89:1d:1d:61:15:0c:75:36:9c:ca:7d:78:bf:b2:a9:
        68:2e:b5:01:81:a3:87:12:03:4a:49:7e:18:9c:9a:28:8f:7d:
        d5:68:4c:9f:84:48:a4:ef:2f:df:5c:97:8f:1e:8e:99:fe:86:
        09:2c:9c:55:e9:c6:a0:1e:6a:f0:90:33:07:c7:cb:a3:bd:dc:
        81:0f:3a:2e:6b:6f:41:20:e1:f4:46:f7:d9:04:3e:70:4f:c5:
        26:ae:78:3e:da:28:83:72:84:d3:fe:28:2b:b3:73:1d:12:2a:
        81:ee:0d:dc:4e:a1:6b:24:9d:fa:33:46:47:5a:8c:0e:ae:69:
        f6:1e:52:c8:f9:7d:e2:94:2f:ba:5a:80:79:0e:b7:5b:62:02:
        56:b9:31:c6:b8:6d:f7:b2:14:30:af:78:8a:e7:b8:d3:72:0a:
        b1:10:9c:80:b7:1e:f6:ea:3d:08:f8:a5:ba:58:bf:ab:f6:fe:
        da:ca:43:68
-----BEGIN CERTIFICATE-----
MIIGZTCCBU2gAwIBAgICP0IwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTE2MTEwODE4MjAzOFoXDTE5
MTEwODE4MjAzOFowVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0Eg
MjAxNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6dNXlvJbX0kINu
E79TUMrNHJbUHGuB8oqbD0an37fv/+1EWc6Hlm9fV7H+M6tHx4WXdzyKDhTNL3lq
JxTSeFulpUs4Orjf9osL2lMRI1mfqWIykPQaTwWDPj3NmxV7kNiLoc3MuMBDn82n
i74jQX0pM99ZfUDA49pzw69Dv5ZYSsKDsiriIX6Tl2r5FWmMfgxokTrwtyyBWgq9
koa5hJmSmASf1MSJwpHhIVJIft0An4/5LT7y6F4KVMxPgkgvDAJeB7Yy5JMpN8xW
dyF2ZhqZ8gsT4sP5O+CYHJw/9SPIhi+Py+m/XxriaDIHvbu2N4neuHD9yMmDRCsY
voZ3EjkCAwEAAaOCAzcwggMzMA8GA1UdEwEB/wQFMAMBAf8wggFBBgNVHSAEggE4
MIIBNDAMBgpghkgBZQMCAQMGMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDCDAM
BgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxAwDAYKYIZIAWUDAgEDATAMBgpghkgB
ZQMCAQMCMAwGCmCGSAFlAwIBAw4wDAYKYIZIAWUDAgEDDzAMBgpghkgBZQMCAQMR
MAwGCmCGSAFlAwIBAxIwDAYKYIZIAWUDAgEDEzAMBgpghkgBZQMCAQMUMAwGCmCG
SAFlAwIBAyQwDAYKYIZIAWUDAgEDAzAMBgpghkgBZQMCAQMEMAwGCmCGSAFlAwIB
AwwwDAYKYIZIAWUDAgEDJTAMBgpghkgBZQMCAQMmMAwGCmCGSAFlAwIBAycwDAYK
YIZIAWUDAgEDKDAMBgpghkgBZQMCAQMpME8GCCsGAQUFBwEBBEMwQTA/BggrBgEF
BQcwAoYzaHR0cDovL2h0dHAuZnBraS5nb3YvZmNwY2EvY2FDZXJ0c0lzc3VlZFRv
ZmNwY2EucDdjMIGNBgNVHSEEgYUwgYIwGAYKYIZIAWUDAgEDBgYKYIZIAWUDAgED
AzAYBgpghkgBZQMCAQMQBgpghkgBZQMCAQMEMBgGCmCGSAFlAwIBAwcGCmCGSAFl
AwIBAwwwGAYKYIZIAWUDAgEDCAYKYIZIAWUDAgEDJTAYBgpghkgBZQMCAQMkBgpg
hkgBZQMCAQMmMFMGCCsGAQUFBwELBEcwRTBDBggrBgEFBQcwBYY3aHR0cDovL2h0
dHAuZnBraS5nb3YvYnJpZGdlL2NhQ2VydHNJc3N1ZWRCeWZiY2EyMDE2LnA3YzAP
BgNVHSQBAf8EBTADgQECMA0GA1UdNgEB/wQDAgEAMA4GA1UdDwEB/wQEAwIBBjAf
BgNVHSMEGDAWgBStDHp1XOXzmMR5mA6sKP2X9OcC/DA1BgNVHR8ELjAsMCqgKKAm
hiRodHRwOi8vaHR0cC5mcGtpLmdvdi9mY3BjYS9mY3BjYS5jcmwwHQYDVR0OBBYE
FCOws30WVNQCVnbrOr6pay9DeygWMA0GCSqGSIb3DQEBCwUAA4IBAQAjrfFl52Vq
vOzz8u/PatFCjkJBDa33wUeVL7w0zu7+l6TsMJSZbPsPZX7upYAQKf2pSWj1stdb
vpe7QLlxGP2bjG+ZXCXiBJUV2+KJHR1hFQx1NpzKfXi/sqloLrUBgaOHEgNKSX4Y
nJooj33VaEyfhEik7y/fXJePHo6Z/oYJLJxV6cagHmrwkDMHx8ujvdyBDzoua29B
IOH0RvfZBD5wT8Umrng+2iiDcoTT/igrs3MdEiqB7g3cTqFrJJ36M0ZHWowOrmn2
HlLI+X3ilC+6WoB5DrdbYgJWuTHGuG33shQwr3iK57jTcgqxEJyAtx726j0I+KW6
WL+r9v7aykNo
-----END CERTIFICATE-----
`

// HexHashFederalBridgeCA2016SignedByFederalCommonPolicyCA is the hex SHA256
// fingerprint ofFederalBridgeCA2016SignedByFederalCommonPolicyCA.
const HexHashFederalBridgeCA2016SignedByFederalCommonPolicyCA = "039c1473089282fb36a4dbc23b1125aec83219c6e624fd169b02e08e6409c3f2"

// PEMFederalCommonPolicyCASignedBySelf is the self-signed certificate for the
// Federal Common Policy CA.
const PEMFederalCommonPolicyCASignedBySelf = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 304 (0x130)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Validity
            Not Before: Dec  1 16:45:27 2010 GMT
            Not After : Dec  1 16:45:27 2030 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d8:75:fb:35:16:34:5a:41:bf:5a:af:5c:30:04:
                    14:1c:ad:78:44:b5:ea:26:ea:75:61:c7:cd:36:79:
                    f8:7c:d8:bd:29:51:66:59:21:e3:79:ab:d4:78:be:
                    b0:2d:b0:a1:d5:b2:35:16:23:d0:cc:1e:be:0e:e8:
                    ab:dc:c3:c9:d6:12:d7:a7:72:68:18:31:b8:17:22:
                    b2:3e:7e:ba:08:6d:c6:fd:d1:58:2c:69:a0:03:f0:
                    2a:a3:f6:3f:21:25:3d:df:b7:32:c5:8e:27:b3:23:
                    a5:e0:52:b3:5d:96:e9:b0:b8:c5:c5:9f:bb:c5:a0:
                    6e:82:40:bb:c5:27:05:36:49:d6:26:27:69:0c:34:
                    8f:cf:27:7a:2a:0a:a3:41:5f:8d:1d:03:86:83:15:
                    e0:55:c1:c5:98:2c:9e:ec:1a:72:dc:48:c1:3e:f9:
                    84:d2:84:82:c1:1b:c3:74:36:b7:b9:c7:36:32:7a:
                    f8:32:b6:d0:36:ae:22:18:31:8c:50:73:21:9e:fe:
                    83:3b:30:88:24:e3:e9:c1:7e:de:ed:98:c7:1f:92:
                    10:8a:9f:5b:62:2f:9d:a4:bc:d5:85:6f:3a:fd:c9:
                    53:a7:20:4b:aa:db:20:ab:21:4e:1d:0d:4e:e6:98:
                    85:e5:ab:11:47:5d:9d:3f:c4:23:c0:e3:14:06:6e:
                    fe:9d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/fcpca/caCertsIssuedByfcpca.p7c
                CA Repository - URI:ldap://ldap.fpki.gov/cn=Federal%20Common%20Policy%20CA,ou=FPKI,o=U.S.%20Government,c=US?cACertificate;binary,crossCertificatePair;binary

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC
    Signature Algorithm: sha256WithRSAEncryption
        8f:73:da:e1:7f:80:b1:87:f6:ec:2c:cf:d1:84:63:1e:f6:f1:
        88:b7:9a:f2:11:b5:ef:54:ad:8a:6e:18:37:28:ef:5c:1b:e4:
        ef:50:b7:6c:26:18:23:22:4d:1d:26:47:20:e9:09:9c:e2:70:
        62:71:ab:11:cf:91:89:e8:b3:f5:2a:a0:47:c0:14:cb:4e:42:
        c1:dd:0c:0e:1b:f0:87:5b:ec:e5:77:d7:aa:e0:54:d7:45:f4:
        85:3e:ec:b4:1d:de:7c:8a:7f:5b:4d:9c:96:8a:d0:a2:32:9f:
        da:6c:31:0c:f8:a4:ef:7e:73:e8:91:dc:08:7a:70:5a:a0:af:
        62:81:59:f8:00:74:a2:c8:dd:54:ca:41:56:47:bd:e9:c0:4f:
        ed:20:dd:e3:a5:09:df:ae:28:c2:fc:d1:c8:17:d8:12:c7:6f:
        de:2e:e9:bd:9a:91:f2:3c:5a:94:2e:91:22:80:89:a1:8c:58:
        cc:83:7a:26:19:75:02:a5:0e:7d:0a:26:73:51:ea:86:cb:07:
        a8:c8:fd:63:5a:35:9b:d2:af:bf:4f:31:48:c1:84:70:db:35:
        7b:9a:19:0f:e5:8f:f4:6a:0c:6f:33:d9:eb:1c:70:a2:0d:e3:
        b9:50:03:61:02:ff:4a:ec:92:a4:dc:2d:ee:2a:34:93:07:b7:
        2c:e7:18:8f
-----BEGIN CERTIFICATE-----
MIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw
MTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s
aWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/
Wq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+
Duir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl
4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF
mCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp
wX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj
wOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH
AQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh
L2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v
bGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es
b3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti
aW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB
BjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD
ggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi
TR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+
7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH
venAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl
Dn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ
A2EC/0rskqTcLe4qNJMHtyznGI8=
-----END CERTIFICATE-----
`

// HexHashFederalCommonPolicyCASignedBySelf is the hex SHA256 fingerprint of
// FederalCommonPolicyCASignedBySelf.
const HexHashFederalCommonPolicyCASignedBySelf = "894ebc0b23da2a50c0186b7f8f25ef1f6b2935af32a94584ef80aaf877a3a06e"

// PEMFederalCommonPolicyCASignedByFederalBridgeCA is the certificate for the
// Federal Common Policy CA signed by the Federal Bridge CA.
const PEMFederalCommonPolicyCASignedByFederalBridgeCA = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1905 (0x771)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA
        Validity
            Not Before: Dec 29 18:55:46 2011 GMT
            Not After : Dec 29 18:53:04 2014 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d8:75:fb:35:16:34:5a:41:bf:5a:af:5c:30:04:
                    14:1c:ad:78:44:b5:ea:26:ea:75:61:c7:cd:36:79:
                    f8:7c:d8:bd:29:51:66:59:21:e3:79:ab:d4:78:be:
                    b0:2d:b0:a1:d5:b2:35:16:23:d0:cc:1e:be:0e:e8:
                    ab:dc:c3:c9:d6:12:d7:a7:72:68:18:31:b8:17:22:
                    b2:3e:7e:ba:08:6d:c6:fd:d1:58:2c:69:a0:03:f0:
                    2a:a3:f6:3f:21:25:3d:df:b7:32:c5:8e:27:b3:23:
                    a5:e0:52:b3:5d:96:e9:b0:b8:c5:c5:9f:bb:c5:a0:
                    6e:82:40:bb:c5:27:05:36:49:d6:26:27:69:0c:34:
                    8f:cf:27:7a:2a:0a:a3:41:5f:8d:1d:03:86:83:15:
                    e0:55:c1:c5:98:2c:9e:ec:1a:72:dc:48:c1:3e:f9:
                    84:d2:84:82:c1:1b:c3:74:36:b7:b9:c7:36:32:7a:
                    f8:32:b6:d0:36:ae:22:18:31:8c:50:73:21:9e:fe:
                    83:3b:30:88:24:e3:e9:c1:7e:de:ed:98:c7:1f:92:
                    10:8a:9f:5b:62:2f:9d:a4:bc:d5:85:6f:3a:fd:c9:
                    53:a7:20:4b:aa:db:20:ab:21:4e:1d:0d:4e:e6:98:
                    85:e5:ab:11:47:5d:9d:3f:c4:23:c0:e3:14:06:6e:
                    fe:9d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.4
                Policy: 2.16.840.1.101.3.2.1.3.21
                Policy: 2.16.840.1.101.3.2.1.3.22
                Policy: 2.16.840.1.101.3.2.1.3.23
                Policy: 2.16.840.1.101.3.2.1.3.24
                Policy: 2.16.840.1.101.3.2.1.3.25
                Policy: 2.16.840.1.101.3.2.1.3.26
                Policy: 2.16.840.1.101.3.2.1.3.27
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.38

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.3.2.1.3.6, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.3.7, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.3.2.1.3.8, 2.16.840.1.101.3.2.1.3.4:2.16.840.1.101.3.2.1.3.16, 2.16.840.1.101.3.2.1.3.38:2.16.840.1.101.3.2.1.3.36
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/fcpca/caCertsIssuedByfcpca.p7c

            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:C4:9D:FC:9D:5D:3A:5D:05:7A:BF:02:81:EC:DB:49:70:15:C7:B2:72

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca.crl

            X509v3 Subject Key Identifier:
                AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC
    Signature Algorithm: sha256WithRSAEncryption
        3c:fb:d6:ac:b6:07:3b:af:87:c5:6d:36:44:41:91:3e:a9:ee:
        1e:96:e9:1d:96:6d:2b:af:4f:4e:a3:5b:b4:38:e3:be:96:b4:
        d0:be:7a:38:2c:c6:7c:1a:ce:a3:90:ed:bb:25:6c:f3:68:cd:
        9c:30:ea:ed:0f:1f:12:87:e2:24:41:1d:92:e2:00:50:62:6d:
        65:13:88:4e:4b:3e:af:b3:df:f7:4f:3f:78:8f:ae:1f:9e:1d:
        76:39:aa:d7:3c:1d:9f:f3:2f:60:44:2e:1c:03:8e:bd:ab:0b:
        92:fd:02:4a:17:81:f8:4e:3a:26:a3:36:d9:cd:ad:a4:ee:4d:
        21:ec:2d:39:a1:2a:6b:79:e8:e4:2d:dc:ea:25:02:37:86:4b:
        d5:3a:45:3a:d8:03:76:46:e1:1d:44:47:74:9d:d2:c3:4d:fe:
        e7:cb:ac:80:23:b0:50:3e:bc:5a:d3:36:8e:97:ae:4d:1f:0f:
        46:0e:84:3a:29:88:27:94:65:a0:d2:b6:a7:9b:db:7f:65:0d:
        e9:e9:de:57:b5:ed:33:bf:27:10:bc:69:5c:06:db:ba:b0:0e:
        f9:e2:67:9a:80:5b:47:5c:6f:82:04:6c:b6:11:7e:cb:68:a8:
        0e:59:5a:96:f9:a6:de:94:d4:eb:f1:65:9d:a1:ee:26:fc:33:
        06:b5:78:78
-----BEGIN CERTIFICATE-----
MIIGLjCCBRagAwIBAgICB3EwDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEaMBgGA1UE
AxMRRmVkZXJhbCBCcmlkZ2UgQ0EwHhcNMTExMjI5MTg1NTQ2WhcNMTQxMjI5MTg1
MzA0WjBZMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQ0w
CwYDVQQLEwRGUEtJMSEwHwYDVQQDExhGZWRlcmFsIENvbW1vbiBQb2xpY3kgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYdfs1FjRaQb9ar1wwBBQc
rXhEteom6nVhx802efh82L0pUWZZIeN5q9R4vrAtsKHVsjUWI9DMHr4O6Kvcw8nW
EtencmgYMbgXIrI+froIbcb90VgsaaAD8Cqj9j8hJT3ftzLFjiezI6XgUrNdlumw
uMXFn7vFoG6CQLvFJwU2SdYmJ2kMNI/PJ3oqCqNBX40dA4aDFeBVwcWYLJ7sGnLc
SME++YTShILBG8N0Nre5xzYyevgyttA2riIYMYxQcyGe/oM7MIgk4+nBft7tmMcf
khCKn1tiL52kvNWFbzr9yVOnIEuq2yCrIU4dDU7mmIXlqxFHXZ0/xCPA4xQGbv6d
AgMBAAGjggMFMIIDATAPBgNVHRMBAf8EBTADAQH/MIIBMwYDVR0gBIIBKjCCASYw
DAYKYIZIAWUDAgEDAjAMBgpghkgBZQMCAQMDMAwGCmCGSAFlAwIBAwwwDAYKYIZI
AWUDAgEDATAMBgpghkgBZQMCAQMOMAwGCmCGSAFlAwIBAw8wDAYKYIZIAWUDAgED
JTAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxQwDAYKYIZIAWUDAgEDEzAMBgpg
hkgBZQMCAQMEMAwGCmCGSAFlAwIBAxUwDAYKYIZIAWUDAgEDFjAMBgpghkgBZQMC
AQMXMAwGCmCGSAFlAwIBAxgwDAYKYIZIAWUDAgEDGTAMBgpghkgBZQMCAQMaMAwG
CmCGSAFlAwIBAxswDAYKYIZIAWUDAgEDETAMBgpghkgBZQMCAQMNMAwGCmCGSAFl
AwIBAyYwTwYIKwYBBQUHAQEEQzBBMD8GCCsGAQUFBzAChjNodHRwOi8vaHR0cC5m
cGtpLmdvdi9icmlkZ2UvY2FDZXJ0c0lzc3VlZFRvZmJjYS5wN2MwgY0GA1UdIQSB
hTCBgjAYBgpghkgBZQMCAQMDBgpghkgBZQMCAQMGMBgGCmCGSAFlAwIBAwwGCmCG
SAFlAwIBAwcwGAYKYIZIAWUDAgEDJQYKYIZIAWUDAgEDCDAYBgpghkgBZQMCAQME
BgpghkgBZQMCAQMQMBgGCmCGSAFlAwIBAyYGCmCGSAFlAwIBAyQwTwYIKwYBBQUH
AQsEQzBBMD8GCCsGAQUFBzAFhjNodHRwOi8vaHR0cC5mcGtpLmdvdi9mY3BjYS9j
YUNlcnRzSXNzdWVkQnlmY3BjYS5wN2MwDgYDVR0PAQH/BAQDAgEGMB8GA1UdIwQY
MBaAFMSd/J1dOl0Fer8CgezbSXAVx7JyMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6
Ly9odHRwLmZwa2kuZ292L2JyaWRnZS9mYmNhLmNybDAdBgNVHQ4EFgQUrQx6dVzl
85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQADggEBADz71qy2Bzuvh8VtNkRB
kT6p7h6W6R2WbSuvT06jW7Q4476WtNC+ejgsxnwazqOQ7bslbPNozZww6u0PHxKH
4iRBHZLiAFBibWUTiE5LPq+z3/dPP3iPrh+eHXY5qtc8HZ/zL2BELhwDjr2rC5L9
AkoXgfhOOiajNtnNraTuTSHsLTmhKmt56OQt3OolAjeGS9U6RTrYA3ZG4R1ER3Sd
0sNN/ufLrIAjsFA+vFrTNo6Xrk0fD0YOhDopiCeUZaDStqeb239lDenp3le17TO/
JxC8aVwG27qwDvniZ5qAW0dcb4IEbLYRfstoqA5ZWpb5pt6U1OvxZZ2h7ib8Mwa1
eHg=
-----END CERTIFICATE-----
`

// HexHashFederalCommonPolicyCASignedByFederalBridgeCA is the hex SHA256
// fingeprint ofFederalCommonPolicyCASignedByFederalBridgeCA.
const HexHashFederalCommonPolicyCASignedByFederalBridgeCA = "96289a5f9a419d10c9cf3739c477a3fb8cd1c56f8f69528b97a2dbb1b6a3270f"

// PEMFederalCommonPolicyCASignedByFederalBridgeCA2013 is the certificate for
// the Federal Common Policy CA signed by the Federal Bridge CA 2013.
const PEMFederalCommonPolicyCASignedByFederalBridgeCA2013 = `
-----BEGIN CERTIFICATE-----
MIIGaTCCBVGgAwIBAgICFlwwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UE
AxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxMzAeFw0xNTA2MjQxNTUyMDdaFw0xODA2
MjQxNTUyMDdaMFkxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDTALBgNVBAsTBEZQS0kxITAfBgNVBAMTGEZlZGVyYWwgQ29tbW9uIFBvbGlj
eSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANh1+zUWNFpBv1qv
XDAEFByteES16ibqdWHHzTZ5+HzYvSlRZlkh43mr1Hi+sC2wodWyNRYj0Mwevg7o
q9zDydYS16dyaBgxuBcisj5+ughtxv3RWCxpoAPwKqP2PyElPd+3MsWOJ7MjpeBS
s12W6bC4xcWfu8WgboJAu8UnBTZJ1iYnaQw0j88neioKo0FfjR0DhoMV4FXBxZgs
nuwactxIwT75hNKEgsEbw3Q2t7nHNjJ6+DK20DauIhgxjFBzIZ7+gzswiCTj6cF+
3u2Yxx+SEIqfW2IvnaS81YVvOv3JU6cgS6rbIKshTh0NTuaYheWrEUddnT/EI8Dj
FAZu/p0CAwEAAaOCAzswggM3MA8GA1UdEwEB/wQFMAMBAf8wUwYIKwYBBQUHAQEE
RzBFMEMGCCsGAQUFBzAChjdodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2UvY2FD
ZXJ0c0lzc3VlZFRvZmJjYTIwMTMucDdjMIIBQQYDVR0gBIIBODCCATQwDAYKYIZI
AWUDAgEDATAMBgpghkgBZQMCAQMCMAwGCmCGSAFlAwIBAwMwDAYKYIZIAWUDAgED
DDAMBgpghkgBZQMCAQMOMAwGCmCGSAFlAwIBAw8wDAYKYIZIAWUDAgEDJTAMBgpg
hkgBZQMCAQMmMAwGCmCGSAFlAwIBAwQwDAYKYIZIAWUDAgEDEjAMBgpghkgBZQMC
AQMTMAwGCmCGSAFlAwIBAxQwDAYKYIZIAWUDAgEDBjAMBgpghkgBZQMCAQMHMAwG
CmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMNMAwGCmCGSAFl
AwIBAxAwDAYKYIZIAWUDAgEDETAMBgpghkgBZQMCAQMoMAwGCmCGSAFlAwIBAykw
DAYKYIZIAWUDAgEDJzBPBggrBgEFBQcBCwRDMEEwPwYIKwYBBQUHMAWGM2h0dHA6
Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCB
jQYDVR0hBIGFMIGCMBgGCmCGSAFlAwIBAwMGCmCGSAFlAwIBAwYwGAYKYIZIAWUD
AgEDBAYKYIZIAWUDAgEDEDAYBgpghkgBZQMCAQMMBgpghkgBZQMCAQMHMBgGCmCG
SAFlAwIBAyUGCmCGSAFlAwIBAwgwGAYKYIZIAWUDAgEDJgYKYIZIAWUDAgEDJDAN
BgNVHTYBAf8EAwIBADAPBgNVHSQBAf8EBTADgQEBMA4GA1UdDwEB/wQEAwIBBjAf
BgNVHSMEGDAWgBS7znRxgzROWTJFFV9AYGDcK7C05DA5BgNVHR8EMjAwMC6gLKAq
hihodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2UvZmJjYTIwMTMuY3JsMB0GA1Ud
DgQWBBStDHp1XOXzmMR5mA6sKP2X9OcC/DANBgkqhkiG9w0BAQsFAAOCAQEAfcpu
K1Y69/mTqMBJ7RV2rNfTExexIdU67nwadpT2izyN4qUKFyCN3jXl1P32pSUr1Moz
Ml7NOA5oHRYC88I1D5auCymCW55sOt5fs9QAbNbM9nwhbyq6ROMDH68j4nV6sb2D
g7slYPbf5UbacCmqIGzjGpks349Cpi3/2Kd1brzx4/13tinNlC9Vocs1RyCDecC7
NJNoE6nApq43m3Ns598EY6aVlXHpCWA913A+yUG4H7rmm4fr+5MrXT79j8iqTLR3
ZbE+MYKadMsXhFkpcp2J4hKPsoycvRXegy00411ZLkUcn48Ha8DdDJSktUQgJolZ
IeSPIo86WvJEwAAVhg==
-----END CERTIFICATE-----`

// HexHashFederalCommonPolicyCASignedByFederalBridgeCA2013 is the hex SHA256
// fingerprint ofFederalCommonPolicyCASignedByFederalBridgeCA2013.
const HexHashFederalCommonPolicyCASignedByFederalBridgeCA2013 = "59cb0702bc82d6a6c58eedbf84e610c3d9ce4630e61fba5745ded0cb371e675c"

// PEMFederalCommonPolicyCASignedByFederalBridgeCA2016 is the certificate for
// the Federal Common Policy CA signed by the Federal Bridge CA 2016.
const PEMFederalCommonPolicyCASignedByFederalBridgeCA2016 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:6f:fe:26:1a:79:65:43:cd:c7:88:e1:5f:90:f5:e3:ec:e6:9b:f4
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA 2016
        Validity
            Not Before: Nov  8 18:14:36 2016 GMT
            Not After : Nov  8 18:14:36 2019 GMT
        Subject: C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d8:75:fb:35:16:34:5a:41:bf:5a:af:5c:30:04:
                    14:1c:ad:78:44:b5:ea:26:ea:75:61:c7:cd:36:79:
                    f8:7c:d8:bd:29:51:66:59:21:e3:79:ab:d4:78:be:
                    b0:2d:b0:a1:d5:b2:35:16:23:d0:cc:1e:be:0e:e8:
                    ab:dc:c3:c9:d6:12:d7:a7:72:68:18:31:b8:17:22:
                    b2:3e:7e:ba:08:6d:c6:fd:d1:58:2c:69:a0:03:f0:
                    2a:a3:f6:3f:21:25:3d:df:b7:32:c5:8e:27:b3:23:
                    a5:e0:52:b3:5d:96:e9:b0:b8:c5:c5:9f:bb:c5:a0:
                    6e:82:40:bb:c5:27:05:36:49:d6:26:27:69:0c:34:
                    8f:cf:27:7a:2a:0a:a3:41:5f:8d:1d:03:86:83:15:
                    e0:55:c1:c5:98:2c:9e:ec:1a:72:dc:48:c1:3e:f9:
                    84:d2:84:82:c1:1b:c3:74:36:b7:b9:c7:36:32:7a:
                    f8:32:b6:d0:36:ae:22:18:31:8c:50:73:21:9e:fe:
                    83:3b:30:88:24:e3:e9:c1:7e:de:ed:98:c7:1f:92:
                    10:8a:9f:5b:62:2f:9d:a4:bc:d5:85:6f:3a:fd:c9:
                    53:a7:20:4b:aa:db:20:ab:21:4e:1d:0d:4e:e6:98:
                    85:e5:ab:11:47:5d:9d:3f:c4:23:c0:e3:14:06:6e:
                    fe:9d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Certificate Policies:
                Policy: 2.16.840.1.101.3.2.1.3.13
                Policy: 2.16.840.1.101.3.2.1.3.1
                Policy: 2.16.840.1.101.3.2.1.3.2
                Policy: 2.16.840.1.101.3.2.1.3.14
                Policy: 2.16.840.1.101.3.2.1.3.15
                Policy: 2.16.840.1.101.3.2.1.3.17
                Policy: 2.16.840.1.101.3.2.1.3.18
                Policy: 2.16.840.1.101.3.2.1.3.19
                Policy: 2.16.840.1.101.3.2.1.3.20
                Policy: 2.16.840.1.101.3.2.1.3.3
                Policy: 2.16.840.1.101.3.2.1.3.12
                Policy: 2.16.840.1.101.3.2.1.3.4
                Policy: 2.16.840.1.101.3.2.1.3.37
                Policy: 2.16.840.1.101.3.2.1.3.38
                Policy: 2.16.840.1.101.3.2.1.3.6
                Policy: 2.16.840.1.101.3.2.1.3.7
                Policy: 2.16.840.1.101.3.2.1.3.8
                Policy: 2.16.840.1.101.3.2.1.3.36
                Policy: 2.16.840.1.101.3.2.1.3.16
                Policy: 2.16.840.1.101.3.2.1.3.39
                Policy: 2.16.840.1.101.3.2.1.3.40
                Policy: 2.16.840.1.101.3.2.1.3.41

            Authority Information Access:
                CA Issuers - URI:http://http.fpki.gov/bridge/caCertsIssuedTofbca2016.p7c

            X509v3 Policy Mappings:
                2.16.840.1.101.3.2.1.3.3:2.16.840.1.101.3.2.1.3.6, 2.16.840.1.101.3.2.1.3.4:2.16.840.1.101.3.2.1.3.16, 2.16.840.1.101.3.2.1.3.12:2.16.840.1.101.3.2.1.3.7, 2.16.840.1.101.3.2.1.3.37:2.16.840.1.101.3.2.1.3.8, 2.16.840.1.101.3.2.1.3.38:2.16.840.1.101.3.2.1.3.36
            Subject Information Access:
                CA Repository - URI:http://http.fpki.gov/fcpca/caCertsIssuedByfcpca.p7c

            X509v3 Policy Constraints: critical
                Inhibit Policy Mapping:1
            X509v3 Inhibit Any Policy: critical
                0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Authority Key Identifier:
                keyid:23:B0:B3:7D:16:54:D4:02:56:76:EB:3A:BE:A9:6B:2F:43:7B:28:16

            X509v3 CRL Distribution Points:
                URI:http://http.fpki.gov/bridge/fbca2016.crl

            X509v3 Subject Key Identifier:
                AD:0C:7A:75:5C:E5:F3:98:C4:79:98:0E:AC:28:FD:97:F4:E7:02:FC
    Signature Algorithm: sha256WithRSAEncryption
        67:c8:d1:37:2d:db:6c:88:3a:4f:93:42:3b:89:c6:46:d7:cb:
        38:23:6f:bd:15:ff:1b:a9:f3:f0:0c:7b:14:6d:ff:c6:b6:50:
        cb:d8:f0:0f:29:9d:a7:4c:10:4c:9d:6f:2a:1b:69:43:43:6f:
        d0:1c:54:df:3c:35:3b:3b:a3:2a:80:fa:cb:b9:9b:e4:4b:2e:
        9c:65:d5:8b:b4:65:b7:0d:4b:25:56:42:69:70:b8:d0:37:c3:
        54:4a:b1:e2:15:5d:d0:97:68:16:5b:81:05:8b:3c:5d:91:1d:
        bd:ed:6c:a1:b9:04:01:f3:54:86:7e:4b:30:29:25:a8:66:f9:
        e6:34:8f:49:d5:c3:37:91:c9:de:dd:ef:27:9c:63:5d:b7:96:
        6e:c4:c0:87:44:da:dd:9e:e9:64:0e:68:b0:c2:b1:df:d5:70:
        5c:8b:56:63:26:81:7c:2c:4e:2d:16:fd:36:ef:b0:12:aa:f1:
        a6:57:7c:de:91:84:26:9c:ef:47:b4:96:7c:18:ab:7d:56:1a:
        dc:4d:64:1e:2c:e3:4e:c3:35:19:8e:e9:8e:d1:c6:c0:cd:a2:
        62:02:54:b8:9c:16:df:61:c7:3f:1c:25:33:00:2b:e3:3c:46:
        e5:eb:ff:55:4c:46:86:66:70:f5:b6:e4:6c:bb:e6:2e:f5:d7:
        10:66:fa:05
-----BEGIN CERTIFICATE-----
MIIGezCCBWOgAwIBAgIUe2/+Jhp5ZUPNx4jhX5D14+zmm/QwDQYJKoZIhvcNAQEL
BQAwVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsG
A1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxNjAeFw0x
NjExMDgxODE0MzZaFw0xOTExMDgxODE0MzZaMFkxCzAJBgNVBAYTAlVTMRgwFgYD
VQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxITAfBgNVBAMTGEZl
ZGVyYWwgQ29tbW9uIFBvbGljeSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANh1+zUWNFpBv1qvXDAEFByteES16ibqdWHHzTZ5+HzYvSlRZlkh43mr
1Hi+sC2wodWyNRYj0Mwevg7oq9zDydYS16dyaBgxuBcisj5+ughtxv3RWCxpoAPw
KqP2PyElPd+3MsWOJ7MjpeBSs12W6bC4xcWfu8WgboJAu8UnBTZJ1iYnaQw0j88n
eioKo0FfjR0DhoMV4FXBxZgsnuwactxIwT75hNKEgsEbw3Q2t7nHNjJ6+DK20Dau
IhgxjFBzIZ7+gzswiCTj6cF+3u2Yxx+SEIqfW2IvnaS81YVvOv3JU6cgS6rbIKsh
Th0NTuaYheWrEUddnT/EI8DjFAZu/p0CAwEAAaOCAzswggM3MA8GA1UdEwEB/wQF
MAMBAf8wggFBBgNVHSAEggE4MIIBNDAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIB
AwEwDAYKYIZIAWUDAgEDAjAMBgpghkgBZQMCAQMOMAwGCmCGSAFlAwIBAw8wDAYK
YIZIAWUDAgEDETAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMwDAYKYIZIAWUD
AgEDFDAMBgpghkgBZQMCAQMDMAwGCmCGSAFlAwIBAwwwDAYKYIZIAWUDAgEDBDAM
BgpghkgBZQMCAQMlMAwGCmCGSAFlAwIBAyYwDAYKYIZIAWUDAgEDBjAMBgpghkgB
ZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMQ
MAwGCmCGSAFlAwIBAycwDAYKYIZIAWUDAgEDKDAMBgpghkgBZQMCAQMpMFMGCCsG
AQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJp
ZGdlL2NhQ2VydHNJc3N1ZWRUb2ZiY2EyMDE2LnA3YzCBjQYDVR0hBIGFMIGCMBgG
CmCGSAFlAwIBAwMGCmCGSAFlAwIBAwYwGAYKYIZIAWUDAgEDBAYKYIZIAWUDAgED
EDAYBgpghkgBZQMCAQMMBgpghkgBZQMCAQMHMBgGCmCGSAFlAwIBAyUGCmCGSAFl
AwIBAwgwGAYKYIZIAWUDAgEDJgYKYIZIAWUDAgEDJDBPBggrBgEFBQcBCwRDMEEw
PwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2NhQ2VydHNJ
c3N1ZWRCeWZjcGNhLnA3YzAPBgNVHSQBAf8EBTADgQEBMA0GA1UdNgEB/wQDAgEA
MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBQjsLN9FlTUAlZ26zq+qWsvQ3so
FjA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2Uv
ZmJjYTIwMTYuY3JsMB0GA1UdDgQWBBStDHp1XOXzmMR5mA6sKP2X9OcC/DANBgkq
hkiG9w0BAQsFAAOCAQEAZ8jRNy3bbIg6T5NCO4nGRtfLOCNvvRX/G6nz8Ax7FG3/
xrZQy9jwDymdp0wQTJ1vKhtpQ0Nv0BxU3zw1OzujKoD6y7mb5EsunGXVi7Rltw1L
JVZCaXC40DfDVEqx4hVd0JdoFluBBYs8XZEdve1sobkEAfNUhn5LMCklqGb55jSP
SdXDN5HJ3t3vJ5xjXbeWbsTAh0Ta3Z7pZA5osMKx39VwXItWYyaBfCxOLRb9Nu+w
Eqrxpld83pGEJpzvR7SWfBirfVYa3E1kHizjTsM1GY7pjtHGwM2iYgJUuJwW32HH
PxwlMwAr4zxG5ev/VUxGhmZw9bbkbLvmLvXXEGb6BQ==
-----END CERTIFICATE-----
`

// HexHashFederalCommonPolicyCASignedByFederalBridgeCA2016 is the hex SHA256
// fingerprint ofFederalCommonPolicyCASignedByFederalBridgeCA2016.
const HexHashFederalCommonPolicyCASignedByFederalBridgeCA2016 = "343293348becda9784b09e5e252a25355772e488cb75dc8b5075dc89541b3cc9"
