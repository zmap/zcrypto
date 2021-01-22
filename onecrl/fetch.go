package onecrl

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/mozilla/OneCRL-Tools/oneCRL"
)

// OneCRL represents parsed response
type OneCRL struct {
	// Set provides a map of Issuer DN in RFC4514 format to a list of serial numbers
	Set map[string][][]byte
}

// KintoRequestURL specifies a pre-populated URL where to send request
var KintoRequestURL = "https://settings.prod.mozaws.net/v1/buckets/security-state-staging/collections/onecrl/records"

// Fetch returns the current fetched CRLSet
func Fetch() (*OneCRL, error) {
	existing, err := oneCRL.FetchExistingRevocations(KintoRequestURL)
	if err != nil {
		return nil, fmt.Errorf("onecrl: failed to fetch: %v", err)
	}

	res := &OneCRL{
		Set: make(map[string][][]byte),
	}
	for _, entry := range existing.Data {
		if entry.IssuerName == "" {
			// TODO: add to the list by Subject and PubKeyHash
			continue
		}

		rawSerial, err := base64.StdEncoding.DecodeString(entry.SerialNumber)
		if err != nil {
			log.Printf("onecrl: invalid SerialNumber%s\n", entry.SerialNumber)
		}

		issuerName, err := oneCRL.DNToRFC4514(entry.IssuerName)
		if err != nil || issuerName == "" {
			log.Printf("onecrl: found invalid IssuerName: %q, serial: %s\n", entry.IssuerName, entry.SerialNumber)
		} else {
			res.Set[issuerName] = append(res.Set[issuerName], rawSerial)
		}

		// log.Printf("onecrl: %s => %s\n", issuerName, entry.SerialNumber)
	}
	return res, nil
}
