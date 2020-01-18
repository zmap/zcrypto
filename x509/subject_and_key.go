package x509

// SubjectAndKey represents a (subjecty, subject public key info) tuple.
type SubjectAndKey struct {
	RawSubject              []byte
	RawSubjectPublicKeyInfo []byte
	Fingerprint             CertificateFingerprint
	PublicKey               interface{}
	PublicKeyAlgorithm      PublicKeyAlgorithm
}

// SubjectAndKey returns a SubjectAndKey for this certificate.
func (c *Certificate) SubjectAndKey() *SubjectAndKey {
	return &SubjectAndKey{
		RawSubject:              c.RawSubject,
		RawSubjectPublicKeyInfo: c.RawSubjectPublicKeyInfo,
		Fingerprint:             c.SPKISubjectFingerprint,
		PublicKey:               c.PublicKey,
		PublicKeyAlgorithm:      c.PublicKeyAlgorithm,
	}
}
