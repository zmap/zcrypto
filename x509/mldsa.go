package x509

import (
	"bytes"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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
func ParseMLDSA44PrivateKey(der []byte) (*mldsa44.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa44.SeedSize {
				return nil, errors.New("x509: invalid MLDSA44 seed length")
			}

			var seed [mldsa44.SeedSize]byte
			copy(seed[:], raw.Bytes)

			_, priv := mldsa44.NewKeyFromSeed(&seed)
			return priv, nil
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		if len(both.Seed) != mldsa44.SeedSize {
			return nil, errors.New("x509: invalid MLDSA44 seed length in 'both' private key")
		}
		if len(both.ExpandedKey) != mldsa44.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA44 expanded private key length in 'both' private key")
		}

		var seed [mldsa44.SeedSize]byte
		copy(seed[:], both.Seed)

		_, priv := mldsa44.NewKeyFromSeed(&seed)
		expandedFromSeed, err := priv.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expandedFromSeed, both.ExpandedKey) {
			return nil, errors.New("x509: inconsistent MLDSA44 seed and expanded private key in 'both'")
		}

		return priv, nil
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		if len(expandedKey) != mldsa44.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA44 expanded private key length")
		}
		var priv mldsa44.PrivateKey
		if err := priv.UnmarshalBinary(expandedKey); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	return nil, errors.New("x509: failed to parse MLDSA44 private key")
}

func ParseMLDSA65PrivateKey(der []byte) (*mldsa65.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa65.SeedSize {
				return nil, errors.New("x509: invalid MLDSA65 seed length")
			}

			var seed [mldsa65.SeedSize]byte
			copy(seed[:], raw.Bytes)

			_, priv := mldsa65.NewKeyFromSeed(&seed)
			return priv, nil
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		if len(both.Seed) != mldsa65.SeedSize {
			return nil, errors.New("x509: invalid MLDSA65 seed length in 'both' private key")
		}
		if len(both.ExpandedKey) != mldsa65.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA65 expanded private key length in 'both' private key")
		}

		var seed [mldsa65.SeedSize]byte
		copy(seed[:], both.Seed)

		_, priv := mldsa65.NewKeyFromSeed(&seed)
		expandedFromSeed, err := priv.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expandedFromSeed, both.ExpandedKey) {
			return nil, errors.New("x509: inconsistent MLDSA65 seed and expanded private key in 'both'")
		}

		return priv, nil
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		if len(expandedKey) != mldsa65.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA65 expanded private key length")
		}
		var priv mldsa65.PrivateKey
		if err := priv.UnmarshalBinary(expandedKey); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	return nil, errors.New("x509: failed to parse MLDSA65 private key")
}

func ParseMLDSA87PrivateKey(der []byte) (*mldsa87.PrivateKey, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 {
		if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound {
			if len(raw.Bytes) != mldsa87.SeedSize {
				return nil, errors.New("x509: invalid MLDSA87 seed length")
			}

			var seed [mldsa87.SeedSize]byte
			copy(seed[:], raw.Bytes)

			_, priv := mldsa87.NewKeyFromSeed(&seed)
			return priv, nil
		}
	}

	var both struct {
		Seed        []byte
		ExpandedKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &both); err == nil && len(rest) == 0 {
		if len(both.Seed) != mldsa87.SeedSize {
			return nil, errors.New("x509: invalid MLDSA87 seed length in 'both' private key")
		}
		if len(both.ExpandedKey) != mldsa87.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA87 expanded private key length in 'both' private key")
		}

		var seed [mldsa87.SeedSize]byte
		copy(seed[:], both.Seed)

		_, priv := mldsa87.NewKeyFromSeed(&seed)
		expandedFromSeed, err := priv.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expandedFromSeed, both.ExpandedKey) {
			return nil, errors.New("x509: inconsistent MLDSA87 seed and expanded private key in 'both'")
		}

		return priv, nil
	}

	var expandedKey []byte
	if rest, err := asn1.Unmarshal(der, &expandedKey); err == nil && len(rest) == 0 {
		if len(expandedKey) != mldsa87.PrivateKeySize {
			return nil, errors.New("x509: invalid MLDSA87 expanded private key length")
		}
		var priv mldsa87.PrivateKey
		if err := priv.UnmarshalBinary(expandedKey); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	return nil, errors.New("x509: failed to parse MLDSA87 private key")
}
