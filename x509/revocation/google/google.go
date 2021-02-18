package google

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"

	"github.com/zmap/zcrypto/x509"
)

// Provider specifies CRLSet provider interface
type Provider interface {
	FetchAndParse() (*CRLSet, error)
}

// CRLSet - data structure for storing CRLSet data, used by methods below
type CRLSet struct {
	Version      string
	IssuerLists  map[string]*IssuerList
	Sequence     int
	NumParents   int
	BlockedSPKIs []string
}

// IssuerList - list of revoked certificate entries for a given issuer
type IssuerList struct {
	SPKIHash string // SHA256 of Issuer SPKI
	Entries  []*Entry
}

// Entry - entry for a single certificate
type Entry struct {
	SerialNumber *big.Int
}

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

// FetchAndParse - fetch from distribution point, parse to CRLSet struct as defined above
func FetchAndParse() (*CRLSet, error) {
	return NewProvider(VersionRequestURL()).FetchAndParse()
}

// FetchAndParse - fetch from distribution point, parse to CRLSet struct as defined above
func (p *defaultProvider) FetchAndParse() (*CRLSet, error) {
	crlSetReader, version, err := Fetch(p.requestURL)
	if err != nil {
		return nil, err
	}
	return Parse(crlSetReader, version)
}

// Check - Given a parsed CRLSet, check if a given cert is present
func (crlSet *CRLSet) Check(cert *x509.Certificate, issuerSPKIHash string) *Entry {
	// check for BlockedSPKIs first
	for _, spki := range crlSet.BlockedSPKIs {
		if issuerSPKIHash == spki {
			return &Entry{
				SerialNumber: cert.SerialNumber,
			}
		}
	}

	issuersRevokedCerts := crlSet.IssuerLists[issuerSPKIHash]
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

// Implementation details below - includes home-baked parsing of Google Update data,
// originally found at https://github.com/agl/crlset-tools

// Types for Google Update Data - used as wrapper for CRLSet
type update struct {
	XMLName xml.Name    `xml:"gupdate"`
	Apps    []updateApp `xml:"app"`
}

type updateApp struct {
	AppID       string `xml:"appid,attr"`
	UpdateCheck updateCheck
}

type updateCheck struct {
	XMLName xml.Name `xml:"updatecheck"`
	URL     string   `xml:"codebase,attr"`
	Version string   `xml:"version,attr"`
}

// crlSetAppID is the hex(ish) encoded public key hash of the key that signs
// the CRL sets.
const crlSetAppID = "hfnkpimlhhgieaddgfemjhofmfblmnib"

// VersionRequestURL returns a URL from which the current CRLSet version
// information can be fetched.
func VersionRequestURL() string {
	args := url.Values(make(map[string][]string))
	args.Add("x", "id="+crlSetAppID+"&v=&uc"+"&acceptformat=crx3")

	return (&url.URL{
		Scheme:   "https",
		Host:     "clients2.google.com",
		Path:     "/service/update2/crx",
		RawQuery: args.Encode(),
	}).String()
}

// CRXHeader reflects the binary header of a CRX file.
type CRXHeader struct {
	Magic     [4]byte
	Version   uint32
	HeaderLen uint32
}

// ZipReader is a small wrapper around a []byte which implements ReadAt.
type ZipReader []byte

// ReadAt - Implementation of ReadAt for ZipReader App
func (z ZipReader) ReadAt(p []byte, pos int64) (int, error) {
	if int(pos) < 0 {
		return 0, nil
	}
	return copy(p, []byte(z)[int(pos):]), nil
}

// Fetch returns reader to be passed to Parse
func Fetch(url string) ([]byte, string, error) {
	resp, err := http.Get(url)
	if err != nil {
		err = errors.New("Failed to get current version: " + err.Error())
		return nil, "", err
	}

	var reply update
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		err = errors.New("Failed to read version reply: " + err.Error())
		return nil, "", err
	}
	if err = xml.Unmarshal(bodyBytes, &reply); err != nil {
		err = errors.New("Failed to parse version reply: " + err.Error())
		return nil, "", err
	}

	var crxURL, version string
	for _, app := range reply.Apps {
		if app.AppID == crlSetAppID {
			crxURL = app.UpdateCheck.URL
			version = app.UpdateCheck.Version
			break
		}
	}

	if len(crxURL) == 0 {
		err = errors.New("Failed to parse Omaha response")
		return nil, version, err
	}

	resp, err = http.Get(crxURL)
	if err != nil {
		err = errors.New("Failed to get CRX: " + err.Error())
		return nil, version, err
	}
	defer resp.Body.Close()

	// zip needs to seek around, so we read the whole reply into memory.
	crxBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.New("Failed to download CRX: " + err.Error())
		return nil, version, err
	}
	crx := bytes.NewBuffer(crxBytes)

	var header CRXHeader
	if err = binary.Read(crx, binary.LittleEndian, &header); err != nil {
		err = errors.New("Failed to parse CRX header: " + err.Error())
		return nil, version, err
	}

	if !bytes.Equal(header.Magic[:], []byte("Cr24")) || int(header.HeaderLen) < 0 {
		err = errors.New("Downloaded file doesn't look like a CRX")
		return nil, version, err
	}

	protoHeader := crx.Next(int(header.HeaderLen))
	if len(protoHeader) != int(header.HeaderLen) {
		err = errors.New("Downloaded file doesn't look like a CRX")
		return nil, version, err
	}

	zipBytes := crx.Bytes()
	zipReader := ZipReader(crx.Bytes())

	z, err := zip.NewReader(zipReader, int64(len(zipBytes)))
	if err != nil {
		err = errors.New("Failed to parse ZIP file: " + err.Error())
		return nil, version, err
	}

	var crlFile *zip.File
	for _, file := range z.File {
		if file.Name == "crl-set" {
			crlFile = file
			break
		}
	}

	if crlFile == nil {
		err = errors.New("Downloaded CRX didn't contain a CRLSet")
		return nil, version, err
	}

	crlSetReader, err := crlFile.Open()
	if err != nil {
		err = errors.New("Failed to open crl-set in ZIP: " + err.Error())
		return nil, version, err
	}

	raw, err := ioutil.ReadAll(crlSetReader)
	if err != nil {
		return nil, version, err
	}

	return raw, version, nil
}

// CRLSetHeader is used to parse the JSON header found in CRLSet files.
type CRLSetHeader struct {
	Sequence     int
	NumParents   int
	BlockedSPKIs []string
}

// RawEntry - structure for a raw CRLSet entry
type RawEntry struct {
	SPKIHash   [32]byte // SHA256 of Issuer SPKI
	NumSerials uint32
	Serials    []RawCRLSetSerial
}

// RawCRLSetSerial - structure of certificate serial number in a raw CRLSet entry
type RawCRLSetSerial struct {
	Len         uint8
	SerialBytes []byte
}

// Parse - given a reader for a raw byte stream for a CRLSet,
// parse the file into a usable CRLSet struct instance.
// DUE TO THE DIFFICULTY OF RETRIEVING A CRLSET, IT IS HIGHLY RECOMMENDED
// TO JUST USE THE FetchAndParseCRLSet FUNCTION PROVIDED ABOVE
func Parse(in []byte, version string) (*CRLSet, error) {
	header, remainingBytes, err := getHeader(in)
	if err != nil {
		return nil, err
	}

	rest := bytes.NewReader(remainingBytes)

	crlSet := CRLSet{}
	crlSet.IssuerLists = map[string]*IssuerList{}
	crlSet.Sequence = header.Sequence
	crlSet.Version = version
	crlSet.NumParents = header.NumParents
	crlSet.BlockedSPKIs = header.BlockedSPKIs

	for rest.Len() > 0 {
		rawEntry := RawEntry{}
		issuerList := IssuerList{}
		err := binary.Read(rest, binary.LittleEndian, &rawEntry.SPKIHash)
		if err != nil {
			return nil, err
		}

		issuerList.SPKIHash = hex.EncodeToString(rawEntry.SPKIHash[:])
		crlSet.IssuerLists[issuerList.SPKIHash] = &issuerList

		err = binary.Read(rest, binary.LittleEndian, &rawEntry.NumSerials)
		if err != nil {
			return nil, err
		}

		for i := uint32(0); i < rawEntry.NumSerials; i++ {
			if rest.Len() < 1 {
				err = errors.New("CRLSet truncated at serial length")
				return nil, err
			}
			serial := RawCRLSetSerial{}
			entry := Entry{}
			issuerList.Entries = append(issuerList.Entries, &entry)
			err = binary.Read(rest, binary.LittleEndian, &serial.Len)
			if err != nil {
				return nil, err
			}

			if rest.Len() < int(serial.Len) {
				err = errors.New("CRLSet truncated at serial")
				return nil, err
			}

			serialBytes := make([]byte, serial.Len)
			err = binary.Read(rest, binary.LittleEndian, &serialBytes)
			if err != nil {
				return nil, err
			}
			serialNumber := new(big.Int)
			serialNumber.SetBytes(serialBytes)
			entry.SerialNumber = serialNumber
		}
	}

	return &crlSet, nil
}

// internal method for parsing header when parsing a CRLSet
func getHeader(c []byte) (header CRLSetHeader, rest []byte, err error) {
	if len(c) < 2 {
		err = errors.New("CRLSet truncated at header length")
		return
	}

	headerLen := int(binary.LittleEndian.Uint16(c[0:]))
	c = c[2:]

	if len(c) < headerLen {
		err = errors.New("CRLSet truncated at header")
		return
	}
	headerBytes := c[:headerLen]
	c = c[headerLen:]

	if err = json.Unmarshal(headerBytes, &header); err != nil {
		err = errors.New("Failed to parse header: " + err.Error())
		return
	}

	return header, c, nil
}
