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

// PEMDoDRootCA3SignedByDoDInteropCA2 is the PEM of a certificate for the DoD
// Root CA 3 signed by DoD Interoperability CA 2.
const PEMDoDRootCA3SignedByDoDInteropCA2 string = `
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

// HexSPKISubjectFingerprintDoDRootCA3 is the hex of the SPKI Subject
// Fingerprint for the DoD Root CA 3.
const HexSPKISubjectFingerprintDoDRootCA3 = "e90ccfd162ae66b7d6e9771abf6c461837c813a5589f693b65c66c3803cf8f4c"

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

// HexSPKISubjectFingerprintDoDInteropCA2 is the hex of the SPKI Subject
// Fingerprint for the DoD Interoperability CA 2.
const HexSPKISubjectFingerprintDoDInteropCA2 = "a55a05216a8f75908ceec798c466e892cd5b505767d057b2204daa111de0c809"
