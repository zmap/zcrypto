#zcrypto

[![Build Status](https://travis-ci.org/zmap/zcrypto.svg?branch=master)](https://travis-ci.org/zmap/zcrypto)

Don't roll your own crypto, they said. 

This repo contains specialized versions of tls and x509. 

#tls (formerly known as ztls)
This is a research TLS library that contains the following modifications: Logging of messages sent by client and server during TLS handshake, Support for multiple TLS versions.

This library is written in Golang and is primarily based on Golang's tls library located at
https://github.com/golang/go/tree/master/src/crypto/tls.
