Contributing
============

ZCrypto is an open-source project and welcomes contributions. 

Goals
-----

The primary goal of ZCrypto is to be able to analyze existing cryptographic systems, rather than to provide cryptographic security to production systems. Please keep this in mind when requesting or developing new features.

Style
-----

ZCrypto attempts to follow Go best practices for coding style and documentation. Please run [goimports](https://godoc.org/golang.org/x/tools/cmd/goimports) on your code before submitting any pull requests. Run [gometalinter](https://github.com/alecthomas/gometalinter) and attend to any easy-to-fix lints. We don't expect all code to be lint free (especially if it's a part of an existing package), but new code shouldn't be full of linter warnings. Documentation is automatically generated based on comments and hosted on [godoc](https://godoc.org/github.com/zmap/zcrypto), so pay extra attention to lints about comment quality.
