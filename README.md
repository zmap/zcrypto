ZCrypto
=======

[![PkgGoDev](https://pkg.go.dev/badge/github.com/zmap/zcrypto)](https://pkg.go.dev/github.com/zmap/zcrypto)

ZCrypto contains specialized versions of tls and x509. It is written in Golang and is primarily based on [Golang's TLS library](https://github.com/golang/go/blob/master/src/crypto/tls).


## IMPORTANT!

> [!WARNING]
>
> ZCrypto is a research library, designed to be used for data collection and analysis, as well as experimenting and prototyping. It should _not_ be used to provide security for production systems.


### zcrypto/tls (formerly known as ZTLS)
A _research_ TLS library based on Golang standard library `crypto/tls` that contains that speaks old TLS versions, export ciphers, logs handshake messages, and is highly configurable. Many scary parts are exposed as public variables. It is primarily used for data collection, and is used by [ZGrab](https://github.com/zmap/zgrab2). Uses `zcrypto/x509`.

### zcrypto/x509

A fork of the Golang stdlib `crypto/x509` that adds the ability to serialize certificates to JSON, and plays nice with CT.

### zcrypto/ct

A fork of the Google Certificate Transparency Golang library, designed to play nice with ZCrypto.

## Documentation

Documentation uses pkg.go.dev. See https://pkg.go.dev/github.com/zmap/zcrypto.
