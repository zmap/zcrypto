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

// PEMISRGRootX1SignedBySelf is the self-signed certificate for the ISRG Root
// X1.
const PEMISRGRootX1SignedBySelf = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Internet Security Research Group, CN=ISRG Root X1
        Validity
            Not Before: Jun  4 11:04:38 2015 GMT
            Not After : Jun  4 11:04:38 2035 GMT
        Subject: C=US, O=Internet Security Research Group, CN=ISRG Root X1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (4096 bit)
                Modulus (4096 bit):
                    00:ad:e8:24:73:f4:14:37:f3:9b:9e:2b:57:28:1c:
                    87:be:dc:b7:df:38:90:8c:6e:3c:e6:57:a0:78:f7:
                    75:c2:a2:fe:f5:6a:6e:f6:00:4f:28:db:de:68:86:
                    6c:44:93:b6:b1:63:fd:14:12:6b:bf:1f:d2:ea:31:
                    9b:21:7e:d1:33:3c:ba:48:f5:dd:79:df:b3:b8:ff:
                    12:f1:21:9a:4b:c1:8a:86:71:69:4a:66:66:6c:8f:
                    7e:3c:70:bf:ad:29:22:06:f3:e4:c0:e6:80:ae:e2:
                    4b:8f:b7:99:7e:94:03:9f:d3:47:97:7c:99:48:23:
                    53:e8:38:ae:4f:0a:6f:83:2e:d1:49:57:8c:80:74:
                    b6:da:2f:d0:38:8d:7b:03:70:21:1b:75:f2:30:3c:
                    fa:8f:ae:dd:da:63:ab:eb:16:4f:c2:8e:11:4b:7e:
                    cf:0b:e8:ff:b5:77:2e:f4:b2:7b:4a:e0:4c:12:25:
                    0c:70:8d:03:29:a0:e1:53:24:ec:13:d9:ee:19:bf:
                    10:b3:4a:8c:3f:89:a3:61:51:de:ac:87:07:94:f4:
                    63:71:ec:2e:e2:6f:5b:98:81:e1:89:5c:34:79:6c:
                    76:ef:3b:90:62:79:e6:db:a4:9a:2f:26:c5:d0:10:
                    e1:0e:de:d9:10:8e:16:fb:b7:f7:a8:f7:c7:e5:02:
                    07:98:8f:36:08:95:e7:e2:37:96:0d:36:75:9e:fb:
                    0e:72:b1:1d:9b:bc:03:f9:49:05:d8:81:dd:05:b4:
                    2a:d6:41:e9:ac:01:76:95:0a:0f:d8:df:d5:bd:12:
                    1f:35:2f:28:17:6c:d2:98:c1:a8:09:64:77:6e:47:
                    37:ba:ce:ac:59:5e:68:9d:7f:72:d6:89:c5:06:41:
                    29:3e:59:3e:dd:26:f5:24:c9:11:a7:5a:a3:4c:40:
                    1f:46:a1:99:b5:a7:3a:51:6e:86:3b:9e:7d:72:a7:
                    12:05:78:59:ed:3e:51:78:15:0b:03:8f:8d:d0:2f:
                    05:b2:3e:7b:4a:1c:4b:73:05:12:fc:c6:ea:e0:50:
                    13:7c:43:93:74:b3:ca:74:e7:8e:1f:01:08:d0:30:
                    d4:5b:71:36:b4:07:ba:c1:30:30:5c:48:b7:82:3b:
                    98:a6:7d:60:8a:a2:a3:29:82:cc:ba:bd:83:04:1b:
                    a2:83:03:41:a1:d6:05:f1:1b:c2:b6:f0:a8:7c:86:
                    3b:46:a8:48:2a:88:dc:76:9a:76:bf:1f:6a:a5:3d:
                    19:8f:eb:38:f3:64:de:c8:2b:0d:0a:28:ff:f7:db:
                    e2:15:42:d4:22:d0:27:5d:e1:79:fe:18:e7:70:88:
                    ad:4e:e6:d9:8b:3a:c6:dd:27:51:6e:ff:bc:64:f5:
                    33:43:4f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
    Signature Algorithm: sha256WithRSAEncryption
        55:1f:58:a9:bc:b2:a8:50:d0:0c:b1:d8:1a:69:20:27:29:08:
        ac:61:75:5c:8a:6e:f8:82:e5:69:2f:d5:f6:56:4b:b9:b8:73:
        10:59:d3:21:97:7e:e7:4c:71:fb:b2:d2:60:ad:39:a8:0b:ea:
        17:21:56:85:f1:50:0e:59:eb:ce:e0:59:e9:ba:c9:15:ef:86:
        9d:8f:84:80:f6:e4:e9:91:90:dc:17:9b:62:1b:45:f0:66:95:
        d2:7c:6f:c2:ea:3b:ef:1f:cf:cb:d6:ae:27:f1:a9:b0:c8:ae:
        fd:7d:7e:9a:fa:22:04:eb:ff:d9:7f:ea:91:2b:22:b1:17:0e:
        8f:f2:8a:34:5b:58:d8:fc:01:c9:54:b9:b8:26:cc:8a:88:33:
        89:4c:2d:84:3c:82:df:ee:96:57:05:ba:2c:bb:f7:c4:b7:c7:
        4e:3b:82:be:31:c8:22:73:73:92:d1:c2:80:a4:39:39:10:33:
        23:82:4c:3c:9f:86:b2:55:98:1d:be:29:86:8c:22:9b:9e:e2:
        6b:3b:57:3a:82:70:4d:dc:09:c7:89:cb:0a:07:4d:6c:e8:5d:
        8e:c9:ef:ce:ab:c7:bb:b5:2b:4e:45:d6:4a:d0:26:cc:e5:72:
        ca:08:6a:a5:95:e3:15:a1:f7:a4:ed:c9:2c:5f:a5:fb:ff:ac:
        28:02:2e:be:d7:7b:bb:e3:71:7b:90:16:d3:07:5e:46:53:7c:
        37:07:42:8c:d3:c4:96:9c:d5:99:b5:2a:e0:95:1a:80:48:ae:
        4c:39:07:ce:cc:47:a4:52:95:2b:ba:b8:fb:ad:d2:33:53:7d:
        e5:1d:4d:6d:d5:a1:b1:c7:42:6f:e6:40:27:35:5c:a3:28:b7:
        07:8d:e7:8d:33:90:e7:23:9f:fb:50:9c:79:6c:46:d5:b4:15:
        b3:96:6e:7e:9b:0c:96:3a:b8:52:2d:3f:d6:5b:e1:fb:08:c2:
        84:fe:24:a8:a3:89:da:ac:6a:e1:18:2a:b1:a8:43:61:5b:d3:
        1f:dc:3b:8d:76:f2:2d:e8:8d:75:df:17:33:6c:3d:53:fb:7b:
        cb:41:5f:ff:dc:a2:d0:61:38:e1:96:b8:ac:5d:8b:37:d7:75:
        d5:33:c0:99:11:ae:9d:41:c1:72:75:84:be:02:41:42:5f:67:
        24:48:94:d1:9b:27:be:07:3f:b9:b8:4f:81:74:51:e1:7a:b7:
        ed:9d:23:e2:be:e0:d5:28:04:13:3c:31:03:9e:dd:7a:6c:8f:
        c6:07:18:c6:7f:de:47:8e:3f:28:9e:04:06:cf:a5:54:34:77:
        bd:ec:89:9b:e9:17:43:df:5b:db:5f:fe:8e:1e:57:a2:cd:40:
        9d:7e:62:22:da:de:18:27
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
`

// HexHashISRGRootX1SignedBySelf is the hex SHA256 fingerprint of
// ISRGRootX1SignedBySelf.
const HexHashISRGRootX1SignedBySelf = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"

// PEMLEX3SignedByISRGRootX1 is the certificate for Let's Encrypt X3 signed by
// the ISRG Root X1.
const PEMLEX3SignedByISRGRootX1 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            d3:b1:72:26:34:23:32:dc:f4:05:28:51:2a:ec:9c:6a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Internet Security Research Group, CN=ISRG Root X1
        Validity
            Not Before: Oct  6 15:43:55 2016 GMT
            Not After : Oct  6 15:43:55 2021 GMT
        Subject: C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:d3:0c:f0:5a:e5:2e:47:b7:72:5d:37:83:b3:
                    68:63:30:ea:d7:35:26:19:25:e1:bd:be:35:f1:70:
                    92:2f:b7:b8:4b:41:05:ab:a9:9e:35:08:58:ec:b1:
                    2a:c4:68:87:0b:a3:e3:75:e4:e6:f3:a7:62:71:ba:
                    79:81:60:1f:d7:91:9a:9f:f3:d0:78:67:71:c8:69:
                    0e:95:91:cf:fe:e6:99:e9:60:3c:48:cc:7e:ca:4d:
                    77:12:24:9d:47:1b:5a:eb:b9:ec:1e:37:00:1c:9c:
                    ac:7b:a7:05:ea:ce:4a:eb:bd:41:e5:36:98:b9:cb:
                    fd:6d:3c:96:68:df:23:2a:42:90:0c:86:74:67:c8:
                    7f:a5:9a:b8:52:61:14:13:3f:65:e9:82:87:cb:db:
                    fa:0e:56:f6:86:89:f3:85:3f:97:86:af:b0:dc:1a:
                    ef:6b:0d:95:16:7d:c4:2b:a0:65:b2:99:04:36:75:
                    80:6b:ac:4a:f3:1b:90:49:78:2f:a2:96:4f:2a:20:
                    25:29:04:c6:74:c0:d0:31:cd:8f:31:38:95:16:ba:
                    a8:33:b8:43:f1:b1:1f:c3:30:7f:a2:79:31:13:3d:
                    2d:36:f8:e3:fc:f2:33:6a:b9:39:31:c5:af:c4:8d:
                    0d:1d:64:16:33:aa:fa:84:29:b6:d4:0b:c0:d8:7d:
                    c3:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.root-x1.letsencrypt.org

            X509v3 Subject Key Identifier:
                A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1
            X509v3 CRL Distribution Points:
                URI:http://crl.root-x1.letsencrypt.org

            Authority Information Access:
                OCSP - URI:http://ocsp.root-x1.letsencrypt.org/
                CA Issuers - URI:http://cert.root-x1.letsencrypt.org/

            X509v3 Authority Key Identifier:
                keyid:79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E

    Signature Algorithm: sha256WithRSAEncryption
        19:cf:75:20:34:2d:3a:a6:45:ff:d0:d5:e6:8c:da:32:e8:9c:
        6e:1b:41:d1:27:a8:e2:50:f2:70:aa:c4:e7:93:46:b4:e8:10:
        ab:70:4f:ef:b7:ea:04:d2:94:11:b1:03:fe:5d:ba:df:36:8c:
        94:36:8f:13:7c:44:8f:0b:f5:01:57:ad:68:b8:c5:79:c0:d8:
        4a:80:d7:4c:a3:1e:24:7a:1f:d7:23:e8:c1:62:3a:76:f9:22:
        7d:5e:5a:c4:4c:50:cd:af:dd:ef:6d:36:c0:80:80:1b:a4:3c:
        70:20:d6:54:21:d3:ba:ef:14:a9:bf:07:3f:41:0a:36:b1:a2:
        b0:0b:20:d5:1f:67:d0:c3:eb:88:f6:8a:02:c8:c6:57:b6:0c:
        fc:56:f1:d2:3f:17:69:68:1c:c8:d7:66:3a:86:f1:19:2a:65:
        47:68:c6:d2:03:e7:ef:74:16:0b:06:21:f9:0c:a6:a8:11:4b:
        4e:5f:e3:33:db:08:41:ea:09:79:75:78:ee:47:c8:42:d3:81:
        c5:65:2d:75:d0:0e:00:16:9d:1c:ee:b7:58:45:25:e7:33:63:
        5b:63:41:09:e8:e9:fe:ac:fa:73:32:74:b3:76:e9:6b:94:e2:
        cd:d4:62:f3:ae:3a:c5:31:46:52:6e:ed:34:91:1e:a0:c2:de:
        54:84:e5:78:20:56:4c:dd:68:f9:2e:28:64:1b:1a:99:f2:fb:
        4d:7f:e3:b8:5f:5d:73:41:ec:79:ed:58:d6:7a:37:65:70:a7:
        b1:ba:39:f6:3e:61:0a:d9:c0:86:90:9a:1a:c8:a8:96:6e:8a:
        0b:2b:6d:ed:d6:fa:07:67:e7:29:04:f7:e2:b2:d1:58:15:52:
        c7:f1:a3:9d:a6:c0:56:2c:d4:92:98:d8:f1:83:b9:6c:7c:33:
        a0:e5:4b:aa:90:92:f1:da:45:4a:34:14:c7:7c:4e:c4:a5:6c:
        5d:3f:bf:de:b9:a8:61:4a:85:20:de:42:83:29:62:7c:1c:99:
        08:a5:46:1f:f4:6b:22:d3:86:51:cb:37:cd:60:4a:42:63:56:
        b3:c8:d1:8f:31:09:53:c1:e2:dc:1b:d4:f1:54:77:67:cf:33:
        7b:00:d6:d2:7c:de:c6:79:bf:cb:e0:16:fd:b2:a1:f2:91:3c:
        1d:2d:e8:9c:d4:03:cd:66:4a:a3:37:93:19:79:7b:e2:19:c2:
        16:00:c8:ed:0e:4e:0d:ff:7e:cf:07:a8:64:cd:29:df:41:aa:
        85:30:49:10:73:a7:4e:89:32:0e:5b:ad:40:86:c1:b0:94:0c:
        8d:26:c5:a7:49:dc:1c:f8:5b:14:7a:7f:23:69:04:ad:b2:02:
        29:d6:12:c8:a4:c6:a1:2d
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----
`

// HexHashPEMLEX3SignedByISRGRootX1 is the hex SHA256 fingerprint of
// LEX3SignedByISRGRootX1.
const HexHashPEMLEX3SignedByISRGRootX1 = "731d3d9cfaa061487a1d71445a42f67df0afca2a6c2d2f98ff7b3ce112b1f568"

// PEMLEX3SignedByDSTRootCAX3 is the certificate for Let's Encrypt Authority X3
// signed by IdenTrust DST Root CA X3.
const PEMLEX3SignedByDSTRootCAX3 = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0a:01:41:42:00:00:01:53:85:73:6a:0b:85:ec:a7:08
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=Digital Signature Trust Co., CN=DST Root CA X3
        Validity
            Not Before: Mar 17 16:40:46 2016 GMT
            Not After : Mar 17 16:40:46 2021 GMT
        Subject: C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:9c:d3:0c:f0:5a:e5:2e:47:b7:72:5d:37:83:b3:
                    68:63:30:ea:d7:35:26:19:25:e1:bd:be:35:f1:70:
                    92:2f:b7:b8:4b:41:05:ab:a9:9e:35:08:58:ec:b1:
                    2a:c4:68:87:0b:a3:e3:75:e4:e6:f3:a7:62:71:ba:
                    79:81:60:1f:d7:91:9a:9f:f3:d0:78:67:71:c8:69:
                    0e:95:91:cf:fe:e6:99:e9:60:3c:48:cc:7e:ca:4d:
                    77:12:24:9d:47:1b:5a:eb:b9:ec:1e:37:00:1c:9c:
                    ac:7b:a7:05:ea:ce:4a:eb:bd:41:e5:36:98:b9:cb:
                    fd:6d:3c:96:68:df:23:2a:42:90:0c:86:74:67:c8:
                    7f:a5:9a:b8:52:61:14:13:3f:65:e9:82:87:cb:db:
                    fa:0e:56:f6:86:89:f3:85:3f:97:86:af:b0:dc:1a:
                    ef:6b:0d:95:16:7d:c4:2b:a0:65:b2:99:04:36:75:
                    80:6b:ac:4a:f3:1b:90:49:78:2f:a2:96:4f:2a:20:
                    25:29:04:c6:74:c0:d0:31:cd:8f:31:38:95:16:ba:
                    a8:33:b8:43:f1:b1:1f:c3:30:7f:a2:79:31:13:3d:
                    2d:36:f8:e3:fc:f2:33:6a:b9:39:31:c5:af:c4:8d:
                    0d:1d:64:16:33:aa:fa:84:29:b6:d4:0b:c0:d8:7d:
                    c3:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            Authority Information Access:
                OCSP - URI:http://isrg.trustid.ocsp.identrust.com
                CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c

            X509v3 Authority Key Identifier:
                keyid:C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10

            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.root-x1.letsencrypt.org

            X509v3 CRL Distribution Points:
                URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl

            X509v3 Subject Key Identifier:
                A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1
    Signature Algorithm: sha256WithRSAEncryption
        dd:33:d7:11:f3:63:58:38:dd:18:15:fb:09:55:be:76:56:b9:
        70:48:a5:69:47:27:7b:c2:24:08:92:f1:5a:1f:4a:12:29:37:
        24:74:51:1c:62:68:b8:cd:95:70:67:e5:f7:a4:bc:4e:28:51:
        cd:9b:e8:ae:87:9d:ea:d8:ba:5a:a1:01:9a:dc:f0:dd:6a:1d:
        6a:d8:3e:57:23:9e:a6:1e:04:62:9a:ff:d7:05:ca:b7:1f:3f:
        c0:0a:48:bc:94:b0:b6:65:62:e0:c1:54:e5:a3:2a:ad:20:c4:
        e9:e6:bb:dc:c8:f6:b5:c3:32:a3:98:cc:77:a8:e6:79:65:07:
        2b:cb:28:fe:3a:16:52:81:ce:52:0c:2e:5f:83:e8:d5:06:33:
        fb:77:6c:ce:40:ea:32:9e:1f:92:5c:41:c1:74:6c:5b:5d:0a:
        5f:33:cc:4d:9f:ac:38:f0:2f:7b:2c:62:9d:d9:a3:91:6f:25:
        1b:2f:90:b1:19:46:3d:f6:7e:1b:a6:7a:87:b9:a3:7a:6d:18:
        fa:25:a5:91:87:15:e0:f2:16:2f:58:b0:06:2f:2c:68:26:c6:
        4b:98:cd:da:9f:0c:f9:7f:90:ed:43:4a:12:44:4e:6f:73:7a:
        28:ea:a4:aa:6e:7b:4c:7d:87:dd:e0:c9:02:44:a7:87:af:c3:
        34:5b:b4:42
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
`

// HexHashPEMLEX3SignedByDSTRootCAX3 is the hex SHA256 fingerprint of
// LEX3SignedByDSTRootCAX3.
const HexHashPEMLEX3SignedByDSTRootCAX3 = "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d"
