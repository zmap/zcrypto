package main

import (
	"flag"
	"fmt"
	"log"

	"encoding/json"
	ct "github.com/zmap/zcrypto/ct"
	"github.com/zmap/zcrypto/ct/client"
	"github.com/zmap/zcrypto/x509"
)

// Processes the given entry in the specified log.
func processEntry(entry ct.LogEntry) (*x509.Certificate, error) {
	cert := &x509.Certificate{}
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		innerCert, err := x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry)
		if err != nil {
			return nil, err
		}
		cert = innerCert
	case ct.PrecertLogEntryType:
		innerCert, err := x509.ParseCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
		if err != nil {
			return nil, err
		}
		cert = innerCert
	}
	return cert, nil
}

func main() {
	var logURI = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
	var indexToParse = flag.Int64("index", 1, "Index to parse")
	flag.Parse()
	logClient := client.New(*logURI)
	entries, err := logClient.GetEntries(*indexToParse, *indexToParse)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range entries {
		cert, err := processEntry(entry)
		if err != nil {
			fmt.Printf("%d %s\n", entry.Index, err.Error())
			continue
		}
		finalJSON, _ := json.Marshal(cert)
		fmt.Printf("%d %s\n", entry.Index, string(finalJSON))
	}
}
