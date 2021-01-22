package crlset

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// CRLSet represents parsed CRLSet response
type CRLSet struct {
	// Sequence specifies the version of CRLSet
	Sequence int
	// NumParents specifies the number of parents in the Set
	NumParents int
	// Set provides a map of hex-encoded SPKI to a list of serial numbers
	Set map[string][][]byte
}

// Fetch returns the current fetched CRLSet
func Fetch() (*CRLSet, error) {
	log.Printf("crlset: fetching CRLSet version from %s\n", VersionRequestURL)

	resp, err := http.Get(VersionRequestURL)
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to get current version: %v", err)
	}

	var reply update
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to read version reply: %v", err)
	}

	if err := xml.Unmarshal(bodyBytes, &reply); err != nil {
		return nil, fmt.Errorf("crlset: failed to parse version reply: %v", err)
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
		return nil, fmt.Errorf("crlset: failed to parse Omaha response: version: %s", version)
	}

	log.Printf("crlset: downloading CRLSet version %s from %s\n", version, crxURL)
	resp, err = http.Get(crxURL)
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to get CRX: %v", err)
	}
	defer resp.Body.Close()

	// zip needs to seek around, so we read the whole reply into memory.
	crxBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to download CRX: %v", err)
	}

	crx := bytes.NewBuffer(crxBytes)

	var header crxHeader
	if err := binary.Read(crx, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("crlset: failed to parse CRX header: %v", err)
	}

	if !bytes.Equal(header.Magic[:], []byte("Cr24")) || int(header.HeaderLen) < 0 {
		return nil, fmt.Errorf("crlset: currupted CRX file")
	}

	protoHeader := crx.Next(int(header.HeaderLen))
	if len(protoHeader) != int(header.HeaderLen) {
		return nil, fmt.Errorf("crlset: currupted CRX file")
	}

	zipBytes := crx.Bytes()
	zipReader := zipReader(crx.Bytes())

	z, err := zip.NewReader(zipReader, int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to parse ZIP file: %v", err)
	}

	var crlFile *zip.File
	for _, file := range z.File {
		if file.Name == "crl-set" {
			crlFile = file
			break
		}
	}

	if crlFile == nil {
		return nil, fmt.Errorf("crlset: missing CRLSet in downloaded CRX")
	}

	crlSetReader, err := crlFile.Open()
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to open crl-set in ZIP: %v", err)
	}
	defer crlSetReader.Close()

	ser, err := ioutil.ReadAll(crlSetReader)
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to load crl-set in ZIP: %v", err)
	}

	return Parse(ser)
}

// Parse returns parsed CRLSet
func Parse(c []byte) (*CRLSet, error) {
	header, c, err := getHeader(c)
	if err != nil {
		return nil, fmt.Errorf("crlset: failed to parse: %v", err)
	}

	res := &CRLSet{
		Sequence:   header.Sequence,
		NumParents: header.NumParents,
		Set:        make(map[string][][]byte),
	}

	for len(c) > 0 {
		const spkiHashLen = 32
		if len(c) < spkiHashLen {
			return nil, fmt.Errorf("crlset: truncated at SPKI hash")
		}
		spki := c[:spkiHashLen]
		key := hex.EncodeToString(spki)
		c = c[spkiHashLen:]

		if len(c) < 4 {
			return nil, fmt.Errorf("crlset:  truncated at serial count")
		}
		numSerials := uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24
		c = c[4:]

		list := make([][]byte, numSerials)

		for i := uint32(0); i < numSerials; i++ {
			if len(c) < 1 {
				return nil, fmt.Errorf("crlset: truncated at serial length")
			}
			serialLen := int(c[0])
			c = c[1:]

			if len(c) < serialLen {
				return nil, fmt.Errorf("crlset: truncated at serial")
			}

			list[i] = c[:serialLen]
			c = c[serialLen:]
		}

		res.Set[key] = list
	}

	return res, nil
}

func getHeader(c []byte) (header *crlSetHeader, rest []byte, err error) {
	if len(c) < 2 {
		return nil, nil, fmt.Errorf("truncated at header length")
	}

	headerLen := int(c[0]) | int(c[1])<<8
	c = c[2:]

	if len(c) < headerLen {
		return nil, nil, fmt.Errorf("truncated at header")
	}
	headerBytes := c[:headerLen]
	c = c[headerLen:]

	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("failed to parse header: %v", err)
	}

	return header, c, nil
}

// update and the related structures are used for parsing the XML response from Omaha. The response looks like:
// <?xml version="1.0" encoding="UTF-8"?>
// <gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod">
//   <daystart elapsed_seconds="42913"/>
//   <app appid="hfnkpimlhhgieaddgfemjhofmfblmnib" status="ok">
//     <updatecheck codebase="http://www.gstatic.com/chrome/crlset/56/crl-set-14830555124393087472.crx.data" hash="" size="0" status="ok" version="56"/>
//   </app>
// </gupdate>
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

// VersionRequestURL specifies a pre-populated URL where to send request
var VersionRequestURL = buildVersionRequestURL()

// buildVersionRequestURL returns a URL from which the current CRLSet version
// information can be fetched.
func buildVersionRequestURL() string {
	args := url.Values(make(map[string][]string))
	args.Add("x", "id="+crlSetAppID+"&v=&uc"+"&acceptformat=crx3")

	return (&url.URL{
		Scheme:   "https",
		Host:     "clients2.google.com",
		Path:     "/service/update2/crx",
		RawQuery: args.Encode(),
	}).String()
}

// crxHeader reflects the binary header of a CRX file.
type crxHeader struct {
	Magic     [4]byte
	Version   uint32
	HeaderLen uint32
}

// zipReader is a small wrapper around a []byte which implements ReaderAt.
type zipReader []byte

func (z zipReader) ReadAt(p []byte, pos int64) (int, error) {
	if int(pos) < 0 {
		return 0, nil
	}
	return copy(p, []byte(z)[int(pos):]), nil
}

// crlSetHeader is used to parse the JSON header found in CRLSet files.
type crlSetHeader struct {
	Sequence                 int
	NumParents               int
	BlockedSPKIs             []string
	KnownInterceptionSPKIs   []string
	BlockedInterceptionSPKIs []string
}
