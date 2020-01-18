package x509

import (
	"crypto"

	"github.com/zmap/zcrypto/x509/pkix"
)

// Certificates returns a list of parsed certificates in the pool.
func (s *CertPool) Certificates() []*Certificate {
	out := make([]*Certificate, 0, len(s.certs))
	out = append(out, s.certs...)
	return out
}

func GetSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) SignatureAlgorithm {
	return getSignatureAlgorithmFromAI(ai)
}

func CheckSignature(algo SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	return checkSignature(algo, signed, signature, publicKey)
}
