package microsoft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// distribution point http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcert.sst

// DisallowedCerts - data structure for storing certificates revoked by
// Microsoft's intermediate revocation mechanism, disallowedcert.sst
type DisallowedCerts struct {
	IssuerLists map[string]*IssuerList
}

// IssuerList - List of revoked cert entries given issuer
type IssuerList struct {
	Issuer  pkix.Name
	Entries []*Entry
}

// Entry - Revocation Data for a single Certificate
type Entry struct {
	SerialNumber *big.Int
}

// Parse raw disallowedcert.sst and return an instance of DisallowedCerts,
// a struct for easy checking of revocation data for certs
func Parse(byteData []byte) (*DisallowedCerts, error) {
	return parse(byteData)
}

// Check - Given a parsed DisallowedCerts instance created by the Parse Func,
// check to see if a provided certificate has been revoked by this list
func Check(disallowed *DisallowedCerts, cert *x509.Certificate) *Entry {
	issuerStr := cert.Issuer.String()
	issuersRevokedCerts := disallowed.IssuerLists[issuerStr]
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

// Structs and methods below are original format for disallowedcert.sst,
// used for parsing raw data from the distribution point
// Implementation details below - includes home-baked parsing Microsoft sst format

// VBASigSerializedCertStore - The serialized digital certificate store specifies
// structures for storing a digital certificate store containing a single digital
// certificate and, optionally, a list of properties associated with the certificate.
type VBASigSerializedCertStore struct {
	Version          uint32  // must be 0x00000000
	Magic            [4]byte // must be CERT in ascii
	CertGroup        CertStoreCertificateGroup
	endMarkerElement EndElementMarkerEntry
}

// CertStoreCertificateGroup - Specifies a grouping of elements in a serialized
// digital certificate store that consists of zero or more properties of a
// certificate, and the serialized certificate itself.
type CertStoreCertificateGroup struct {
	elementList        []SerializedPropertyEntry
	certificateElement SerializedCertificateEntry
}

// SerializedPropertyEntry - Specifies an entry in a serialized digital
// certificate store that contains data for a property associated with a
// certificate in the store.
type SerializedPropertyEntry struct {
	ID           uint32 // MUST be less than or equal to 0x0000FFFF and MUST NOT be the value 0x00000000 or 0x00000020
	EncodingType uint32 // MUST be the value 0x00000001, which specifies ASN.1 encoding
	Length       uint32 // specifies the length of the value field
	Value        []byte
}

// SerializedCertificateEntry - Specifies an entry in a serialized digital
// certificate store that contains data for a property associated with a
// certificate in the store.
type SerializedCertificateEntry struct {
	ID           uint32 //MUST be 0x00000020
	EncodingType uint32 // MUST be the value 0x00000001, which specifies ASN.1 encoding
	Length       uint32 // specifies the length of the certificate field
	Certificate  []byte
}

// EndElementMarkerEntry - Specifies a special entry in a serialized digital
// certificate store that marks the end of the store.
type EndElementMarkerEntry struct {
	ID     uint32 // MUST be 0x00000000
	Marker uint64 // MUST be 0x0000000000000000
}

// Parse through a binary representation of a SST file,
// construct map
func parse(byteData []byte) (*DisallowedCerts, error) {
	bytesReader := bytes.NewReader(byteData)
	var certStore VBASigSerializedCertStore
	binary.Read(bytesReader, binary.LittleEndian, &certStore.Version)
	binary.Read(bytesReader, binary.LittleEndian, &certStore.Magic)

	if !bytes.Equal(certStore.Magic[:], []byte("CERT")) ||
		certStore.Version != 0 {
		err := errors.New("This file doesn't look like an SST")
		return nil, err
	}

	certs := [][]byte{}

	for { // read through element list and certificate elements
		var id uint32
		binary.Read(bytesReader, binary.LittleEndian, &id)
		if id == uint32(0) { // this is EndElementMarkerEntry, we have reached end of list
			break
		}
		var format uint32
		binary.Read(bytesReader, binary.LittleEndian, &format)
		var len uint32
		binary.Read(bytesReader, binary.LittleEndian, &len)
		if id == uint32(32) { // this is a SerializedCertificateEntry
			if format != uint32(1) {
				err := errors.New("SST does not use ASN1 encoding")
				return nil, err
			}
			certChain := make([]byte, len)
			binary.Read(bytesReader, binary.LittleEndian, &certChain)
			certs = append(certs, certChain)
		} else { // this is a SerializedPropertyEntry, so skip it
			io.CopyN(ioutil.Discard, bytesReader, int64(len)) // skip over value bytes
		}
	}

	disallowed := &DisallowedCerts{}
	disallowed.IssuerLists = map[string]*IssuerList{}

	for i := range certs {
		cert, _ := x509.ParseCertificate(certs[i])
		entry := &Entry{
			SerialNumber: cert.SerialNumber,
		}
		issuerStr := cert.Issuer.String()
		issuerList := disallowed.IssuerLists[issuerStr]
		if issuerList != nil { // if list already exists for this issuer, append
			issuerList.Entries = append(issuerList.Entries, entry)
		} else { // create new list for this issuer
			newList := &IssuerList{
				Issuer: cert.Issuer,
			}
			newList.Entries = append(newList.Entries, entry)
			disallowed.IssuerLists[issuerStr] = newList
		}
	}
	return disallowed, nil
}
