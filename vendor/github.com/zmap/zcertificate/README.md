# ZCertificate

[![Build Status](https://travis-ci.org/zmap/zcertificate.svg?branch=master)](https://travis-ci.org/zmap/zcertificate)

ZCertificate parses X.509 certificates and runs [ZLint](https://github.com/zmap/zlint).


### Usage

First, grab the code `go get github.com/zmap/zcertificate/cmd/zcertificate`

```
$ ./zcertificate --help
Usage of ./zcertificate:
  -fatal-parse-errors
    	Halt if a certificate cannot be parsed. Default is to log.
  -format string
    	one of {pem, base64} (default "pem")
  -output-file string
    	Specifies file path for the output JSON. (default "-")
  -procs int
    	Specifies number of processes to run on. Default is 0, meaning use current value of $GOMAXPROCS.
  -workers int
    	Specifies number of goroutines to use to parse and lint certificates. (default 1)

$ cat example.crt | zcertificate | jq .
INFO[0000] reading from stdin
INFO[0000] writing to stdout
{
  "raw": "...",
  "parsed": {
    "version": 3,
    "serial_number": "513",
    "signature_algorithm": {
      "name": "SHA1WithRSA",
      "oid": "1.2.840.113549.1.1.5"
    },
    "issuer": {
      "country": [
        "US"
      ],
  ...
}
```
