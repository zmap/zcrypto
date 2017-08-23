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

// PEMGoogleSignedByGIAG2 is the certificate for google.com signed by the Google
// Internet Authority G2.
const PEMGoogleSignedByGIAG2 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            71:1e:64:e1:d9:28:7b:4e
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, O=Google Inc, CN=Google Internet Authority G2
        Validity
            Not Before: Mar 12 09:38:30 2014 GMT
            Not After : Jun 10 00:00:00 2014 GMT
        Subject: C=US, ST=California, L=Mountain View, O=Google Inc, CN=www.google.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:b8:cd:80:9e:9b:4a:14:06:1c:04:d0:4c:01:af:
                    ae:5e:04:e7:20:71:03:b6:3d:a4:88:00:1d:9d:10:
                    ff:dc:d4:43:17:da:d3:b2:d2:8b:fc:ae:4f:37:78:
                    f8:49:f8:c5:9d:4f:5c:fa:8e:07:bd:5f:8c:d0:40:
                    8f:19:c8:0f:6a:22:2c:2b:28:16:4e:8b:c0:cd:52:
                    fa:ea:35:90:bb:7c:90:15:46:b6:fd:69:7f:fd:f6:
                    e6:0e:24:2c:a9:21:ba:66:58:6d:6a:7e:16:c7:8c:
                    97:b0:87:07:fc:c5:83:e3:ef:57:94:e2:b2:c6:f3:
                    46:be:0d:aa:56:9a:98:6d:7e:ad:e1:e7:69:43:40:
                    80:73:2d:57:f5:c9:86:f2:ad:36:84:2d:ac:f8:35:
                    71:7b:1d:76:f9:62:42:1d:fe:0c:48:b1:2c:cc:d1:
                    a1:54:56:ed:a8:f2:c2:5c:2d:80:2c:26:ac:1f:14:
                    a0:4a:38:cc:54:72:7e:78:e6:79:6c:a5:fd:26:4d:
                    c5:99:d0:03:e5:6f:0b:0a:ce:73:6c:e3:fc:42:0f:
                    02:31:c5:68:e3:aa:01:eb:60:01:65:eb:2d:3b:8b:
                    58:33:6c:03:aa:74:d1:32:47:6e:29:fb:72:56:23:
                    c5:99:06:50:48:76:4d:8a:1a:3d:16:d5:f2:1f:b2:
                    fc:b1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                DNS:www.google.com
            Authority Information Access:
                CA Issuers - URI:http://pki.google.com/GIAG2.crt
                OCSP - URI:http://clients1.google.com/ocsp

            X509v3 Subject Key Identifier:
                D7:0F:90:71:EA:2A:93:F9:D9:84:85:B1:4B:E0:E5:28:1F:26:67:F3
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier:
                keyid:4A:DD:06:16:1B:BC:F6:68:B5:76:F5:81:B6:BB:62:1A:BA:5A:81:2F

            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.11129.2.5.1

            X509v3 CRL Distribution Points:
                URI:http://pki.google.com/GIAG2.crl

    Signature Algorithm: sha1WithRSAEncryption
        91:dd:12:6d:1f:38:03:87:7d:db:fc:c2:35:ba:08:a4:8b:e9:
        e5:f0:89:23:e6:56:ab:6c:94:44:fe:b7:00:e6:88:ad:7b:e4:
        09:c8:0a:fa:49:4d:60:24:9f:eb:46:b2:b7:22:d5:44:1e:bf:
        4b:eb:6d:41:08:ce:c6:49:da:0d:32:30:7d:30:c7:1f:b4:90:
        16:d2:46:06:27:ec:2a:2a:6e:77:c0:6f:c9:68:e0:03:4e:79:
        ea:d8:cb:7f:8f:a1:76:ba:f8:e0:37:fa:2e:9e:cd:67:44:7b:
        9f:22:f7:77:ef:43:74:2d:e1:fe:a2:b2:aa:4e:e0:0f:cd:72:
        bb:8a:64:24:eb:e3:b2:71:80:01:6e:a0:ad:0b:ff:6a:9b:04:
        5d:f3:0c:27:ee:c1:7d:ec:3b:58:7c:af:16:b8:d1:ed:15:a9:
        42:03:0c:a2:f0:bc:49:25:82:42:2d:6a:0c:85:9f:95:f0:66:
        66:f8:53:9e:c7:9a:a4:40:08:e7:66:bb:4d:95:b4:09:f2:ba:
        38:af:ea:e9:29:7b:66:30:51:61:7d:af:bb:2f:e3:c0:2a:89:
        b4:f1:e5:0a:f2:c9:31:03:37:c3:0e:28:d9:3e:1d:74:56:d2:
        7a:ea:e0:68:88:33:dd:4f:eb:82:05:e8:5c:04:87:26:49:3a:
        ca:8c:51:97
-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----
`

// HexHashPEMGoogleSignedByGIAG2 is the hex SHA356 fingerprint of
// GoogleSignedByGIAG2.
const HexHashPEMGoogleSignedByGIAG2 = "e23648ebf04ee37b48d2ae504f673d4c867416519db807b5b9471d20a83097c7"

// PEMGIAG2SignedByGeoTrust is the certificate for the Google Internet Authority
// G2 signed by GeoTrust.
const PEMGIAG2SignedByGeoTrust = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 146025 (0x23a69)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, O=GeoTrust Inc., CN=GeoTrust Global CA
        Validity
            Not Before: Apr  5 15:15:55 2013 GMT
            Not After : Apr  4 15:15:55 2015 GMT
        Subject: C=US, O=Google Inc, CN=Google Internet Authority G2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:2a:04:77:5c:d8:50:91:3a:06:a3:82:e0:d8:
                    50:48:bc:89:3f:f1:19:70:1a:88:46:7e:e0:8f:c5:
                    f1:89:ce:21:ee:5a:fe:61:0d:b7:32:44:89:a0:74:
                    0b:53:4f:55:a4:ce:82:62:95:ee:eb:59:5f:c6:e1:
                    05:80:12:c4:5e:94:3f:bc:5b:48:38:f4:53:f7:24:
                    e6:fb:91:e9:15:c4:cf:f4:53:0d:f4:4a:fc:9f:54:
                    de:7d:be:a0:6b:6f:87:c0:d0:50:1f:28:30:03:40:
                    da:08:73:51:6c:7f:ff:3a:3c:a7:37:06:8e:bd:4b:
                    11:04:eb:7d:24:de:e6:f9:fc:31:71:fb:94:d5:60:
                    f3:2e:4a:af:42:d2:cb:ea:c4:6a:1a:b2:cc:53:dd:
                    15:4b:8b:1f:c8:19:61:1f:cd:9d:a8:3e:63:2b:84:
                    35:69:65:84:c8:19:c5:46:22:f8:53:95:be:e3:80:
                    4a:10:c6:2a:ec:ba:97:20:11:c7:39:99:10:04:a0:
                    f0:61:7a:95:25:8c:4e:52:75:e2:b6:ed:08:ca:14:
                    fc:ce:22:6a:b3:4e:cf:46:03:97:97:03:7e:c0:b1:
                    de:7b:af:45:33:cf:ba:3e:71:b7:de:f4:25:25:c2:
                    0d:35:89:9d:9d:fb:0e:11:79:89:1e:37:c5:af:8e:
                    72:69
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:C0:7A:98:68:8D:89:FB:AB:05:64:0C:11:7D:AA:7D:65:B8:CA:CC:4E

            X509v3 Subject Key Identifier:
                4A:DD:06:16:1B:BC:F6:68:B5:76:F5:81:B6:BB:62:1A:BA:5A:81:2F
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 CRL Distribution Points:
                URI:http://crl.geotrust.com/crls/gtglobal.crl

            Authority Information Access:
                OCSP - URI:http://gtglobal-ocsp.geotrust.com

            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.11129.2.5.1

    Signature Algorithm: sha1WithRSAEncryption
        36:d7:06:80:11:27:ad:2a:14:9b:38:77:b3:23:a0:75:58:bb:
        b1:7e:83:42:ba:72:da:1e:d8:8e:36:06:97:e0:f0:95:3b:37:
        fd:1b:42:58:fe:22:c8:6b:bd:38:5e:d1:3b:25:6e:12:eb:5e:
        67:76:46:40:90:da:14:c8:78:0d:ed:95:66:da:8e:86:6f:80:
        a1:ba:56:32:95:86:dc:dc:6a:ca:04:8c:5b:7f:f6:bf:cc:6f:
        85:03:58:c3:68:51:13:cd:fd:c8:f7:79:3d:99:35:f0:56:a3:
        bd:e0:59:ed:4f:44:09:a3:9e:38:7a:f6:46:d1:1d:12:9d:4f:
        be:d0:40:fc:55:fe:06:5e:3c:da:1c:56:bd:96:51:7b:6f:57:
        2a:db:a2:aa:96:dc:8c:74:c2:95:be:f0:6e:95:13:ff:17:f0:
        3c:ac:b2:10:8d:cc:73:fb:e8:8f:02:c6:f0:fb:33:b3:95:3b:
        e3:c2:cb:68:58:73:db:a8:24:62:3b:06:35:9d:0d:a9:33:bd:
        78:03:90:2e:4c:78:5d:50:3a:81:d4:ee:a0:c8:70:38:dc:b2:
        f9:67:fa:87:40:5d:61:c0:51:8f:6b:83:6b:cd:05:3a:ca:e1:
        a7:05:78:fc:ca:da:94:d0:2c:08:3d:7e:16:79:c8:a0:50:20:
        24:54:33:71
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----
`

// HexHashPEMGIAG2SignedByGeoTrust is the hex SHA256 fingerprint of
// GIAG2SignedByGeoTrust.
const HexHashPEMGIAG2SignedByGeoTrust = "a047a37fa2d2e118a4f5095fe074d6cfe0e352425a7632bf8659c03919a6c81d"

// PEMGeoTrustSignedBySelf is the self-signed certificate for GeoTrust.
const PEMGeoTrustSignedBySelf = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 144470 (0x23456)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, O=GeoTrust Inc., CN=GeoTrust Global CA
        Validity
            Not Before: May 21 04:00:00 2002 GMT
            Not After : May 21 04:00:00 2022 GMT
        Subject: C=US, O=GeoTrust Inc., CN=GeoTrust Global CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:da:cc:18:63:30:fd:f4:17:23:1a:56:7e:5b:df:
                    3c:6c:38:e4:71:b7:78:91:d4:bc:a1:d8:4c:f8:a8:
                    43:b6:03:e9:4d:21:07:08:88:da:58:2f:66:39:29:
                    bd:05:78:8b:9d:38:e8:05:b7:6a:7e:71:a4:e6:c4:
                    60:a6:b0:ef:80:e4:89:28:0f:9e:25:d6:ed:83:f3:
                    ad:a6:91:c7:98:c9:42:18:35:14:9d:ad:98:46:92:
                    2e:4f:ca:f1:87:43:c1:16:95:57:2d:50:ef:89:2d:
                    80:7a:57:ad:f2:ee:5f:6b:d2:00:8d:b9:14:f8:14:
                    15:35:d9:c0:46:a3:7b:72:c8:91:bf:c9:55:2b:cd:
                    d0:97:3e:9c:26:64:cc:df:ce:83:19:71:ca:4e:e6:
                    d4:d5:7b:a9:19:cd:55:de:c8:ec:d2:5e:38:53:e5:
                    5c:4f:8c:2d:fe:50:23:36:fc:66:e6:cb:8e:a4:39:
                    19:00:b7:95:02:39:91:0b:0e:fe:38:2e:d1:1d:05:
                    9a:f6:4d:3e:6f:0f:07:1d:af:2c:1e:8f:60:39:e2:
                    fa:36:53:13:39:d4:5e:26:2b:db:3d:a8:14:bd:32:
                    eb:18:03:28:52:04:71:e5:ab:33:3d:e1:38:bb:07:
                    36:84:62:9c:79:ea:16:30:f4:5f:c0:2b:e8:71:6b:
                    e4:f9
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                C0:7A:98:68:8D:89:FB:AB:05:64:0C:11:7D:AA:7D:65:B8:CA:CC:4E
            X509v3 Authority Key Identifier:
                keyid:C0:7A:98:68:8D:89:FB:AB:05:64:0C:11:7D:AA:7D:65:B8:CA:CC:4E

    Signature Algorithm: sha1WithRSAEncryption
        35:e3:29:6a:e5:2f:5d:54:8e:29:50:94:9f:99:1a:14:e4:8f:
        78:2a:62:94:a2:27:67:9e:d0:cf:1a:5e:47:e9:c1:b2:a4:cf:
        dd:41:1a:05:4e:9b:4b:ee:4a:6f:55:52:b3:24:a1:37:0a:eb:
        64:76:2a:2e:2c:f3:fd:3b:75:90:bf:fa:71:d8:c7:3d:37:d2:
        b5:05:95:62:b9:a6:de:89:3d:36:7b:38:77:48:97:ac:a6:20:
        8f:2e:a6:c9:0c:c2:b2:99:45:00:c7:ce:11:51:22:22:e0:a5:
        ea:b6:15:48:09:64:ea:5e:4f:74:f7:05:3e:c7:8a:52:0c:db:
        15:b4:bd:6d:9b:e5:c6:b1:54:68:a9:e3:69:90:b6:9a:a5:0f:
        b8:b9:3f:20:7d:ae:4a:b5:b8:9c:e4:1d:b6:ab:e6:94:a5:c1:
        c7:83:ad:db:f5:27:87:0e:04:6c:d5:ff:dd:a0:5d:ed:87:52:
        b7:2b:15:02:ae:39:a6:6a:74:e9:da:c4:e7:bc:4d:34:1e:a9:
        5c:4d:33:5f:92:09:2f:88:66:5d:77:97:c7:1d:76:13:a9:d5:
        e5:f1:16:09:11:35:d5:ac:db:24:71:70:2c:98:56:0b:d9:17:
        b4:d1:e3:51:2b:5e:75:e8:d5:d0:dc:4f:34:ed:c2:05:66:80:
        a1:cb:e6:33
-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----
`

// HexHashPEMGeoTrustSignedBySelf is the hex SHA256 fingerprint of
// GeoTrustSignedBySelf.
const HexHashPEMGeoTrustSignedBySelf = "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
