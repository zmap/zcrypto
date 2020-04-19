package x509

import (
	"encoding/asn1"
	"encoding/json"
)

type QCStatementASN struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

func (s *QCStatementASN) MarshalJSON() ([]byte, error) {
	aux := struct {
		ID    string `json:"id,omitempty"`
		Value []byte `json:"value,omitempty"`
	}{
		ID:    s.StatementID.String(),
		Value: s.StatementInfo.Bytes,
	}
	return json.Marshal(&aux)
}

type QCStatementsASN struct {
	QCStatements []QCStatementASN
}

// ETSI OIDS
var (
	oidEtsiQcsQcCompliance      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidEtsiQcsQcLimitValue      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	oidEtsiQcsQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	oidEtsiQcsQcSSCD            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	oidEtsiQcsQcEuPDS           = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	oidEtsiQcsQcType            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
	oidEtsiQcsQctEsign          = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	oidEtsiQcsQctEseal          = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	oidEtsiQcsQctWeb            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

type QCStatements struct {
	StatementIDs     []string            `json:"ids,omitempty"`
	ParsedStatements *ParsedQCStatements `json:"parsed,omitempty"`
}

type ParsedQCStatements struct {
	ETSICompliance  bool           `json:"etsi_compliance,omitempty"`
	SSCD            bool           `json:"sscd,omitempty"`
	Types           *QCType        `json:"qc_types,omitempty"`
	Limit           *MonetaryValue `json:"limit,omitempty"`
	PDSLocations    []PDSLocation  `json:"pds_locations,omitempty"`
	RetentionPeriod int            `json:"retention_peiod,omitempty"`
}

type MonetaryValue struct {
	Currency       string `json:"currency,omitempty"`
	CurrencyNumber int    `json:"currency_number,omitempty"`
	Amount         int    `json:"amount,omitempty"`
	Exponent       int    `json:"exponent,omitempty"`
}

type monetaryValueASNString struct {
	Currency string `asn1:"printable"`
	Amount   int
	Exponent int
}

type monetaryValueASNNumber struct {
	Currency int
	Amount   int
	Exponent int
}

type PDSLocation struct {
	URL      string `json:"url,omitempty" asn1:"ia5"`
	Language string `json:"language,omitempty" asn1:"printable"`
}

type QCType struct {
	TypeIdentifiers []asn1.ObjectIdentifier
}

func (qt *QCType) MarshalJSON() ([]byte, error) {
	aux := struct {
		Types []string `json:"ids,omitempty"`
	}{
		Types: make([]string, len(qt.TypeIdentifiers)),
	}
	for idx := range qt.TypeIdentifiers {
		aux.Types[idx] = qt.TypeIdentifiers[idx].String()
	}
	return json.Marshal(&aux)
}

func (q *QCStatements) Parse(in *QCStatementsASN) error {
	q.StatementIDs = make([]string, len(in.QCStatements))
	known := ParsedQCStatements{}
	for i, s := range in.QCStatements {
		val := in.QCStatements[i].StatementInfo.FullBytes
		q.StatementIDs[i] = s.StatementID.String()
		if s.StatementID.Equal(oidEtsiQcsQcCompliance) {
			known.ETSICompliance = true
		} else if s.StatementID.Equal(oidEtsiQcsQcLimitValue) {
			// TODO
			mvs := monetaryValueASNString{}
			mvn := monetaryValueASNNumber{}
			out := MonetaryValue{}
			if _, err := asn1.Unmarshal(val, &mvs); err == nil {
				out.Currency = mvs.Currency
				out.Amount = mvs.Amount
				out.Exponent = mvs.Exponent
			} else if _, err := asn1.Unmarshal(val, &mvn); err == nil {
				out.CurrencyNumber = mvn.Currency
				out.Amount = mvn.Amount
				out.Exponent = mvn.Exponent
			} else {
				return err
			}
			known.Limit = &out
		} else if s.StatementID.Equal(oidEtsiQcsQcRetentionPeriod) {
			if _, err := asn1.Unmarshal(val, &known.RetentionPeriod); err != nil {
				return err
			}
		} else if s.StatementID.Equal(oidEtsiQcsQcSSCD) {
			known.SSCD = true
		} else if s.StatementID.Equal(oidEtsiQcsQcEuPDS) {
			locations := make([]PDSLocation, 0)
			if _, err := asn1.Unmarshal(val, &locations); err != nil {
				return err
			}
			known.PDSLocations = locations
		} else if s.StatementID.Equal(oidEtsiQcsQcType) {
			typeIds := make([]asn1.ObjectIdentifier, 0)
			if _, err := asn1.Unmarshal(val, &typeIds); err != nil {
				return err
			}
			known.Types = &QCType{
				TypeIdentifiers: typeIds,
			}
		}
	}
	q.ParsedStatements = &known
	return nil
}