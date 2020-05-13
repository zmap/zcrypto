package x509

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type ASN1 interface {
	Tag() asn1.Tag
	Raw() []byte
	SetRaw(raw []byte)
}

type ASN1Version []byte

func (v ASN1Version) Tag() asn1.Tag {
	return asn1.INTEGER.ContextSpecific()
}

func (v ASN1Version) Raw() []byte {
	return v
}

func (v ASN1Version) Integer() (int, error) {
	var out int
	s := cryptobyte.String(v)
	if !s.ReadASN1Integer(&out) {
		return 0, errors.New("fuck")
	}
	return out, nil
}

type ASN1Certificate struct {
	certificate []byte

	Sequence ASN1CertificateSequence
}

type ASN1CertificateSequence struct {
	sequence []byte

	TBSCertificate ASN1TBSCertificate
	Signature      cryptobyte.String
}

func (c *ASN1CertificateSequence) Tag() asn1.Tag {
	return asn1.SEQUENCE
}

func (c *ASN1CertificateSequence) Raw() []byte {
	return c.sequence
}

func (c *ASN1CertificateSequence) SetRaw(raw []byte) {
	c.sequence = raw
}

type ASN1TBSCertificate struct {
	tbsCertificate []byte

	Version            ASN1Version
	SerialNumber       cryptobyte.String
	SignatureAlgorithm cryptobyte.String
	Issuer             cryptobyte.String
	Validity           cryptobyte.String
	Subject            cryptobyte.String
	Extensions         cryptobyte.String
}

func (tbs *ASN1TBSCertificate) Tag() asn1.Tag {
	return asn1.SEQUENCE
}

func ParseInto(out ASN1, in *cryptobyte.String) error {
	t := out.Tag()
	if !in.PeekASN1Tag(t) {
		return fmt.Errorf("expected tag %d, did not get matching tag", t)
	}
	var obj cryptobyte.String
	if !in.ReadASN1(&obj, t) {
		return fmt.Errorf("could not read tag %d into cryptobyte", t)
	}
	out.SetRaw(obj)
	return nil
}

func ParseASN1Certificate(b []byte) (*ASN1Certificate, error) {
	in := cryptobyte.String(b)
	var full cryptobyte.String
	var junkTag asn1.Tag
	in.ReadAnyASN1Element(&full, &junkTag)
	offset := full

	out := ASN1Certificate{}
	out.certificate = full

	sequence := cryptobyte.String(out.Sequence.sequence)
	ParseInto(&out.Sequence, &offset)
	ParseInto(&out.Sequence.TBSCertificate, &offset)
	return &out, nil
}
