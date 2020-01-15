package x509

func (s *CertPool) FindVerifiedParents(cert *Certificate) (parents []int, errCert *Certificate, err error) {
	return s.findVerifiedParents(cert)
}

func (s *CertPool) GetCert(i int) *Certificate {
	return s.certs[i]
}

func (s *CertPool) Certs() []*Certificate {
	return s.certs
}
