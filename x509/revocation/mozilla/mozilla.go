package mozilla

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// const oneCRLDistPoint := "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records"

// OneCRL - data structure for storing OneCRL data, used by methods below
type OneCRL struct {
	IssuerLists map[string]*IssuerList
}

// IssuerList - list of Entry for a given issuer
type IssuerList struct {
	Issuer  pkix.Name
	Entries []*Entry
}

// Entry - entry for a single certificate
type Entry struct {
	Schema       time.Time
	Details      EntryDetails
	Enabled      bool
	Issuer       pkix.Name
	SerialNumber *big.Int
	ID           string
	LastModified time.Time
}

// RawEntry - structure of a raw oneCRL entry
type RawEntry struct {
	Schema       int          `json:"schema"`
	Details      EntryDetails `json:"details"`
	Enabled      bool         `json:"enabled"`
	Issuer       string       `json:"issuerName"`
	SerialNumber string       `json:"serialNumber"`
	ID           string       `json:"id"`
	LastModified int          `json:"last_modified"`
}

// EntryDetails - revocation details for a single entry
type EntryDetails struct {
	Bug     string    `json:"bug,omitempty"`
	Who     string    `json:"who,omitempty"`
	Why     string    `json:"why,omitempty"`
	Name    string    `json:"name,omitempty"`
	Created time.Time `json:"created,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (entry *Entry) UnmarshalJSON(b []byte) error {
	aux := &RawEntry{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	serialNumberBytes, _ := base64.StdEncoding.DecodeString(aux.SerialNumber)
	serialNumber := new(big.Int).SetBytes(serialNumberBytes)
	schemaSeconds := int64(aux.Schema) / 1000
	schema := time.Unix(schemaSeconds, 0)
	lastModifiedSeconds := int64(aux.LastModified) / 1000
	lastModified := time.Unix(lastModifiedSeconds, 0)
	issuerBytes, err := base64.StdEncoding.DecodeString(aux.Issuer)
	if err != nil {
		return err
	}
	var issuerRDN pkix.RDNSequence
	_, err = asn1.Unmarshal(issuerBytes, &issuerRDN)
	if err != nil {
		return err
	}
	var issuer pkix.Name
	issuer.FillFromRDNSequence(&issuerRDN)
	*entry = Entry{
		Schema:       schema,
		Details:      aux.Details,
		Enabled:      aux.Enabled,
		Issuer:       issuer,
		SerialNumber: serialNumber,
		ID:           aux.ID,
		LastModified: lastModified,
	}
	return nil
}

// FindIssuer - given an issuer pkix.name, find its corresponding IssuerList
func (c OneCRL) FindIssuer(issuer pkix.Name) *IssuerList {
	issuerStr := issuer.String()
	return c.IssuerLists[issuerStr]
}

// Parse - given raw bytes of OneCRL, parse and create OneCRL Object
func Parse(raw []byte) (*OneCRL, error) {
	rawOneCRL := struct {
		Data []Entry `json:"data"`
	}{}
	if err := json.Unmarshal(raw, &rawOneCRL); err != nil {
		return nil, errors.New("Could not parse OneCRL" + err.Error())
	}
	oneCRL := &OneCRL{}
	oneCRL.IssuerLists = map[string]*IssuerList{}
	for i := range rawOneCRL.Data {
		entry := &(rawOneCRL.Data[i])
		issuerList := oneCRL.FindIssuer(entry.Issuer)
		if issuerList != nil { // if list already exists for this issuer, append
			issuerList.Entries = append(issuerList.Entries, entry)
		} else { // create new list for this issuer
			newList := &IssuerList{
				Issuer: entry.Issuer,
			}
			newList.Entries = append(newList.Entries, entry)
			oneCRL.IssuerLists[entry.Issuer.String()] = newList
		}
	}
	return oneCRL, nil
}

// Check - Given a parsed OneCRL, check if a given cert is present
func (c *OneCRL) Check(cert *x509.Certificate) *Entry {
	issuersRevokedCerts := c.FindIssuer(cert.Issuer)
	if issuersRevokedCerts == nil { // no entries for this issuer
		return nil
	}
	for _, entry := range issuersRevokedCerts.Entries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return entry
		} // cert not found if for loop completes
	}
	return nil
}
