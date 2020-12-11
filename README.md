ZCrypto
=======

[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zcrypto)](https://goreportcard.com/report/github.com/zmap/zcrypto)
[![GoDoc](https://godoc.org/github.com/zmap/zcrypto?status.svg)](https://godoc.org/github.com/zmap/zcrypto)

ZCrypto contains specialized versions of tls and x509. It is written in Golang and is primarily based on [Golang's TLS library](https://github.com/golang/go/blob/master/src/crypto/tls).


## IMPORTANT!

### ![Danger: Experimental](https://camo.githubusercontent.com/275bc882f21b154b5537b9c123a171a30de9e6aa/68747470733a2f2f7261772e6769746875622e636f6d2f63727970746f7370686572652f63727970746f7370686572652f6d61737465722f696d616765732f6578706572696d656e74616c2e706e67)

ZCrypto is a research library, designed to be used for data collection and analysis, as well as experimenting and prototyping. It should _not_ be used to provide security for production systems.


### zcrypto/tls (formerly known as ZTLS)
A _research_ TLS library based on Golang standard library `crypto/tls` that contains that speaks old TLS versions, export ciphers, logs handshake messages, and is highly configurable. Many scary parts are exposed as public variables. It is primarily used for data collection, and is used by [ZGrab](https://github.com/zmap/zgrab2). Uses `zcrypto/x509`.

### zcrypto/x509

A fork of the Golang stdlib `crypto/x509` that adds the ability to serialize certificates to JSON, and plays nice with CT.

### zcrypto/ct

A fork of the Google Certificate Transparency Golang library, designed to play nice with ZCrypto.

## Documentation

Documentation uses Godoc. See https://godoc.org/github.com/zmap/zcrypto.
