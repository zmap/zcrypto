package x509

import (
	"errors"

	"crypto/mldsa"

	"github.com/zmap/zcrypto/encoding/asn1"
)

// [FIPS204] specifies two formats for an ML-DSA private key: a 32-octet seed (ξ) (GREEK SMALL LETTER XI, U+03BE) and an (expanded) private key.
// The expanded private key (and public key) is computed from the seed using ML-DSA.
// RFC 9881:
//
//	ML-DSA-44-PrivateKey ::= CHOICE {
//	    seed [0] OCTET STRING (SIZE (32)),
//	    expandedKey OCTET STRING (SIZE (2560)),
//	    both SEQUENCE {
//	        seed OCTET STRING (SIZE (32)),
//	        expandedKey OCTET STRING (SIZE (2560))
//	    }
//	}
func ParseMLDSA44PrivateKey(der []byte) (*mldsa.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa.PrivateKeySize {
				return nil, errors.New("x509: invalid MLDSA44 seed length")
			}
			return mldsa.NewPrivateKey(mldsa.MLDSA44(), raw.Bytes)
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA44 private keys with both seed and expanded key are not supported")
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA44 expanded private keys without seed are not supported")
	}

	return nil, errors.New("x509: failed to parse MLDSA44 private key")
}

func ParseMLDSA65PrivateKey(der []byte) (*mldsa.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa.PrivateKeySize {
				return nil, errors.New("x509: invalid MLDSA65 seed length")
			}
			return mldsa.NewPrivateKey(mldsa.MLDSA65(), raw.Bytes)
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA65 private keys with both seed and expanded key are not supported")
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA65 expanded private keys without seed are not supported")
	}

	return nil, errors.New("x509: failed to parse MLDSA65 private key")
}

func ParseMLDSA87PrivateKey(der []byte) (*mldsa.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa.PrivateKeySize {
				return nil, errors.New("x509: invalid MLDSA87 seed length")
			}
			return mldsa.NewPrivateKey(mldsa.MLDSA87(), raw.Bytes)
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA87 private keys with both seed and expanded key are not supported")
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		return nil, errors.New("x509: MLDSA87 expanded private keys without seed are not supported")
	}

	return nil, errors.New("x509: failed to parse MLDSA87 private key")
}
