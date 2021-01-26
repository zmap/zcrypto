package mozilla

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// Provider specifies OneCRL provider interface
type Provider interface {
	FetchAndParse() (*OneCRL, error)
}

const (
	// KintoRequestURL specifies a pre-populated URL where to send request
	KintoRequestURL = "https://settings.prod.mozaws.net/v1/buckets/security-state-staging/collections/onecrl/records"
	// OneCRLDistPoint specifies a pre-populated URL where to send request
	OneCRLDistPoint = "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records"
)

// defaultProvider provides default Provider
type defaultProvider struct {
	requestURL string
}

// NewProvider returns default Provider
func NewProvider(requestURL string) Provider {
	return &defaultProvider{
		requestURL: requestURL,
	}
}

// FetchAndParse - fetch from distribution point, parse to OneCRL struct as defined above
func FetchAndParse() (*OneCRL, error) {
	return NewProvider(OneCRLDistPoint).FetchAndParse()
}

// OneCRL - data structure for storing OneCRL data, used by methods below
type OneCRL struct {
	IssuerLists map[string]*IssuerList

	// Blocked provides a list of revoked entries by Subject and PubKeyHash
	Blocked []*SubjectAndPublicKey
}

// IssuerList - list of Entry for a given issuer
type IssuerList struct {
	Issuer  *pkix.Name
	Entries []*Entry
}

// Entry - entry for a single certificate
type Entry struct {
	ID                  string
	Schema              time.Time
	Details             EntryDetails
	Enabled             bool
	Issuer              *pkix.Name
	SerialNumber        *big.Int
	SubjectAndPublicKey *SubjectAndPublicKey
	LastModified        time.Time
}

// SubjectAndPublicKey specifies a revocation entry by Subject and PubKeyHash
type SubjectAndPublicKey struct {
	Subject    string `json:"subject,omitempty"`
	PubKeyHash string `json:"pubKeyHash,omitempty"`
}

// EntryDetails - revocation details for a single entry
type EntryDetails struct {
	Bug     string     `json:"bug,omitempty"`
	Who     string     `json:"who,omitempty"`
	Why     string     `json:"why,omitempty"`
	Name    string     `json:"name,omitempty"`
	Created *time.Time `json:"created,omitempty"`
}

type record struct {
	ID           string `json:"id,omitempty"`
	IssuerName   string `json:"issuerName,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	Subject      string `json:"subject,omitempty"`
	PubKeyHash   string `json:"pubKeyHash,omitempty"`
	Enabled      bool   `json:"enabled"`
	Schema       int    `json:"schema"`
	LastModified int    `json:"last_modified"`
	Details      struct {
		Who     string `json:"who"`
		Created string `json:"created"`
		Bug     string `json:"bug"`
		Name    string `json:"name"`
		Why     string `json:"why"`
	} `json:"details"`
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (entry *Entry) UnmarshalJSON(b []byte) error {
	aux := &record{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	schemaSeconds := int64(aux.Schema) / 1000
	schema := time.Unix(schemaSeconds, 0)
	lastModifiedSeconds := int64(aux.LastModified) / 1000
	lastModified := time.Unix(lastModifiedSeconds, 0)

	var createdAt *time.Time
	if aux.Details.Created != "" {
		var t time.Time
		if err := t.UnmarshalJSON([]byte(aux.Details.Created)); err == nil {
			createdAt = &t
		}
	}

	var subjectAndPublicKey *SubjectAndPublicKey
	var issuer *pkix.Name
	var serialNumber *big.Int

	if aux.Subject != "" && aux.PubKeyHash != "" {
		subjectAndPublicKey = &SubjectAndPublicKey{
			Subject:    aux.Subject,
			PubKeyHash: aux.PubKeyHash,
		}
	} else {
		serialNumberBytes, _ := base64.StdEncoding.DecodeString(aux.SerialNumber)
		serialNumber = new(big.Int).SetBytes(serialNumberBytes)

		issuerBytes, err := base64.StdEncoding.DecodeString(aux.IssuerName)
		if err != nil {
			return err
		}
		var issuerRDN pkix.RDNSequence
		_, err = asn1.Unmarshal(issuerBytes, &issuerRDN)
		if err != nil {
			return err
		}
		var iss pkix.Name
		iss.FillFromRDNSequence(&issuerRDN)
		issuer = &iss
	}

	*entry = Entry{
		ID:     aux.ID,
		Schema: schema,
		Details: EntryDetails{
			Created: createdAt,
			Who:     aux.Details.Who,
			Bug:     aux.Details.Bug,
			Name:    aux.Details.Name,
			Why:     aux.Details.Why,
		},
		Enabled:             aux.Enabled,
		Issuer:              issuer,
		SerialNumber:        serialNumber,
		SubjectAndPublicKey: subjectAndPublicKey,
		LastModified:        lastModified,
	}
	return nil
}

// FindIssuer - given an issuer pkix.name, find its corresponding IssuerList
func (c *OneCRL) FindIssuer(issuer *pkix.Name) *IssuerList {
	issuerStr := issuer.String()
	return c.IssuerLists[issuerStr]
}

// FetchAndParse - fetch from distribution point, parse to OneCRL struct as defined above
func (p *defaultProvider) FetchAndParse() (*OneCRL, error) {
	raw, err := fetch(p.requestURL)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Failed to get current OneCRL: %v", err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to read OneCRL response: %v", err)
	}
	return bodyBytes, nil
}

// Parse - given raw bytes of OneCRL, parse and create OneCRL Object
func Parse(raw []byte) (*OneCRL, error) {
	rawOneCRL := struct {
		Data []Entry `json:"data"`
	}{}
	if err := json.Unmarshal(raw, &rawOneCRL); err != nil {
		return nil, errors.New("Could not parse OneCRL: " + err.Error())
	}
	oneCRL := &OneCRL{
		IssuerLists: make(map[string]*IssuerList),
		Blocked:     make([]*SubjectAndPublicKey, 0),
	}
	for i := range rawOneCRL.Data {
		entry := &(rawOneCRL.Data[i])

		if entry.SubjectAndPublicKey != nil {
			oneCRL.Blocked = append(oneCRL.Blocked, entry.SubjectAndPublicKey)
			continue
		}

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
	issuersRevokedCerts := c.FindIssuer(&cert.Issuer)
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
