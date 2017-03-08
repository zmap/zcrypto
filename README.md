#zcrypto

[![Build Status](https://travis-ci.org/zmap/zcrypto.svg?branch=master)](https://travis-ci.org/zmap/zcrypto)

This repo contains specialized versions of tls and x509. 

## IMPORTANT!

### ![Danger: Experimental](https://camo.githubusercontent.com/275bc882f21b154b5537b9c123a171a30de9e6aa/68747470733a2f2f7261772e6769746875622e636f6d2f63727970746f7370686572652f63727970746f7370686572652f6d61737465722f696d616765732f6578706572696d656e74616c2e706e67)

ZCrypto is a research library, designed to be used for data collection and analysis, as well as experimenting and prototyping. It should _not_ be used to provide security for production systems.

#tls (formerly known as ztls)
This is a research TLS library that contains the following modifications: Logging of messages sent by client and server during TLS handshake, Support for multiple TLS versions.

This library is written in Golang and is primarily based on Golang's tls library located at
https://github.com/golang/go/tree/master/src/crypto/tls.
