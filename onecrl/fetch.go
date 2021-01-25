package onecrl

import (
	"encoding/base64"
	"fmt"

	"github.com/mozilla/OneCRL-Tools/oneCRL"
)

// OneCRL represents parsed response
type OneCRL struct {
	// Set provides a map of Issuer DN in RFC4514 format to a list of serial numbers
	Set map[string][][]byte

	// ByPublicKey provides a list of revoked entries by Subject and PubKeyHash
	ByPublicKey []SubjectAndPublicKey
}

// SubjectAndPublicKey specifies a revocation entry by Subject and PubKeyHash
type SubjectAndPublicKey struct {
	Subject    string `json:"subject,omitempty"`
	PubKeyHash string `json:"pubKeyHash,omitempty"`
}

// Provider specifies OneCRL provider interface
type Provider interface {
	Fetch() (*OneCRL, error)
}

// Fetch returns the current fetched CRLSet
func Fetch() (*OneCRL, error) {
	return NewProvider(kintoRequestURL).Fetch()
}

// kintoRequestURL specifies a pre-populated URL where to send request
const kintoRequestURL = "https://settings.prod.mozaws.net/v1/buckets/security-state-staging/collections/onecrl/records"

// DefaultProvider provides default Provider
type DefaultProvider struct {
	requestURL string
	log        Logger
}

// NewProvider returns default Provider
func NewProvider(kintoRequestURL string) *DefaultProvider {
	return &DefaultProvider{
		requestURL: kintoRequestURL,
		log:        noopLogger{},
	}
}

// WithLogger allows to specify custom logger
func (p *DefaultProvider) WithLogger(log Logger) *DefaultProvider {
	p.log = log
	return p
}

// Fetch returns the current fetched CRLSet
func (p *DefaultProvider) Fetch() (*OneCRL, error) {
	p.log.Printf("onecrl: fetching from %s\n", p.requestURL)

	existing, err := oneCRL.FetchExistingRevocations(p.requestURL)
	if err != nil {
		return nil, fmt.Errorf("onecrl: failed to fetch: %v", err)
	}

	res := &OneCRL{
		Set: make(map[string][][]byte),
	}
	for _, entry := range existing.Data {
		if entry.Subject != "" && entry.PubKeyHash != "" {
			res.ByPublicKey = append(res.ByPublicKey, SubjectAndPublicKey{
				Subject:    entry.Subject,
				PubKeyHash: entry.PubKeyHash,
			})
			continue
		}

		rawSerial, err := base64.StdEncoding.DecodeString(entry.SerialNumber)
		if err != nil {
			p.log.Printf("onecrl: invalid SerialNumber%s\n", entry.SerialNumber)
		}

		issuerName, err := oneCRL.DNToRFC4514(entry.IssuerName)
		if err != nil || issuerName == "" {
			p.log.Printf("onecrl: found invalid IssuerName: %q, serial: %s\n", entry.IssuerName, entry.SerialNumber)
		} else {
			res.Set[issuerName] = append(res.Set[issuerName], rawSerial)
		}

		// log.Printf("onecrl: %s => %s\n", issuerName, entry.SerialNumber)
	}
	return res, nil
}

// Logger provides a simple log interface
type Logger interface {
	Printf(format string, v ...interface{})
}
type noopLogger struct{}

func (noopLogger) Printf(format string, v ...interface{}) {}
