/*
 * ZCrypto Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/revocation/google"
	"github.com/zmap/zcrypto/x509/revocation/mozilla"

	data "github.com/zmap/zcrypto/data/test/certificates"
)

func loadPEMs(pems []string) (out []*x509.Certificate) {
	for _, s := range pems {
		c := loadPEM(s)
		out = append(out, c)
	}
	return
}

func loadPEM(pemBytes string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil
	}
	c, _ := x509.ParseCertificate(block.Bytes)
	return c
}

func getChainID(chain x509.CertificateChain) string {
	parts := make([]string, 0, len(chain))
	for _, c := range chain {
		hexHash := hex.EncodeToString(c.FingerprintSHA256)
		parts = append(parts, hexHash)
	}
	return strings.Join(parts, "|")
}

type chainError struct {
	Extra, Missing []string
}

func (e *chainError) Error() string {
	out := fmt.Sprintf("missing chains: %v, extra chains: %v", e.Missing, e.Extra)
	return out
}

type parentError struct {
	Extra, Missing []string
}

func (e *parentError) Error() string {
	out := fmt.Sprintf("missing parents: %v, extra parents: %v", e.Missing, e.Extra)
	return out
}

type crlSetLoader func() (*google.CRLSet, error)
type oneCRLLoader func() (*mozilla.OneCRL, error)

type verifyTest struct {
	Name string

	Leaf          string
	Presented     []string
	Intermediates []string
	Roots         []string

	CurrentTime int64
	DNSName     string

	ExpectedChains  [][]int
	ExpiredChains   [][]int
	NeverChains     [][]int
	ExpectedParents []int

	ExpectHostnameError bool

	InRevocationSet bool
	CRLSetFn        crlSetLoader
	OneCRLFn        oneCRLLoader

	certificates                    []*x509.Certificate
	leaf                            *x509.Certificate
	presented, intermediates, roots []*x509.Certificate
}

func (vt *verifyTest) parseSelf() {
	vt.leaf = loadPEM(vt.Leaf)
	vt.presented = loadPEMs(vt.Presented)
	vt.intermediates = loadPEMs(vt.Intermediates)
	vt.roots = loadPEMs(vt.Roots)

	vt.certificates = append(vt.certificates, vt.leaf)
	vt.certificates = append(vt.certificates, vt.presented...)
	vt.certificates = append(vt.certificates, vt.intermediates...)
	vt.certificates = append(vt.certificates, vt.roots...)
}

func (vt *verifyTest) parsedLeaf() *x509.Certificate {
	return vt.leaf
}

func (vt *verifyTest) parsedIntermediates() []*x509.Certificate {
	out := make([]*x509.Certificate, len(vt.intermediates))
	copy(out, vt.intermediates)
	return out
}

func (vt *verifyTest) parsedRoots() []*x509.Certificate {
	out := make([]*x509.Certificate, len(vt.roots))
	copy(out, vt.roots)
	return out
}

func (vt *verifyTest) unionAllExpected() [][]int {
	out := make([][]int, 0, 3)
	current := make([][]int, len(vt.ExpectedChains))
	copy(current, vt.ExpectedChains)
	expired := make([][]int, len(vt.ExpiredChains))
	copy(expired, vt.ExpiredChains)
	never := make([][]int, len(vt.NeverChains))
	copy(never, vt.NeverChains)
	out = append(out, current...)
	out = append(out, expired...)
	out = append(out, never...)
	return out
}

func (vt *verifyTest) compareChains(expected [][]int, actual []x509.CertificateChain) *chainError {
	type empty struct{}

	expectedChainMap := make(map[string]empty)
	for _, expectedChainIndices := range expected {
		expectedCerts := make([]*x509.Certificate, 0, len(expectedChainIndices))
		for _, certIdx := range expectedChainIndices {
			expectedCerts = append(expectedCerts, vt.certificates[certIdx])
		}
		chainID := getChainID(expectedCerts)
		expectedChainMap[chainID] = empty{}
	}
	actualChainMap := make(map[string]empty)
	for _, chain := range actual {
		chainID := getChainID(chain)
		actualChainMap[chainID] = empty{}
	}

	var missing, extra []string
	for expectedID := range expectedChainMap {
		_, ok := actualChainMap[expectedID]
		if !ok {
			missing = append(missing, expectedID)
		}
	}
	for actualID := range actualChainMap {
		_, ok := expectedChainMap[actualID]
		if !ok {
			extra = append(extra, actualID)
		}
	}

	if len(missing) > 0 || len(extra) > 0 {
		err := chainError{
			Missing: missing,
			Extra:   extra,
		}
		return &err
	}
	return nil
}

func (vt *verifyTest) compareParents(expected []int, actual []*x509.Certificate) *parentError {
	type empty struct{}
	expectedHashMap := make(map[string]empty)
	for _, certIdx := range expected {
		c := vt.certificates[certIdx]
		hexHash := hex.EncodeToString(c.FingerprintSHA256)
		expectedHashMap[hexHash] = empty{}
	}
	actualHashMap := make(map[string]empty)
	for _, c := range actual {
		hexHash := hex.EncodeToString(c.FingerprintSHA256)
		actualHashMap[hexHash] = empty{}
	}

	var missing, extra []string
	for expectedHash := range expectedHashMap {
		_, ok := actualHashMap[expectedHash]
		if !ok {
			missing = append(missing, expectedHash)
		}
	}
	for actualHash := range actualHashMap {
		_, ok := expectedHashMap[actualHash]
		if !ok {
			extra = append(extra, actualHash)
		}
	}

	if len(missing) > 0 || len(extra) > 0 {
		err := parentError{
			Missing: missing,
			Extra:   extra,
		}
		return &err
	}
	return nil
}

func (vt *verifyTest) compareParentSPKISubjectToParents(verifyResult *VerificationResult) error {
	if len(verifyResult.ParentSPKISubjectFingerprint) == 0 && len(verifyResult.Parents) > 0 {
		return fmt.Errorf("got empty ParentSPKISubjectFingerprint, but have %d parents", len(verifyResult.Parents))
	}
	if len(verifyResult.Parents) == 0 && len(verifyResult.ParentSPKISubjectFingerprint) != 0 {
		return fmt.Errorf("got ParentSPKISubjectFingeprint %s, but no parents", verifyResult.ParentSPKISubjectFingerprint.Hex())
	}
	expected := verifyResult.ParentSPKISubjectFingerprint
	for i, parent := range verifyResult.Parents {
		actualParentFp := parent.SPKISubjectFingerprint
		if !bytes.Equal(expected, actualParentFp) {
			return fmt.Errorf("got ParentSPKISubjectFingerprint %s, but parent index %d and hash %s had SPKISubjectFingerprint %s", expected.Hex(), i, parent.FingerprintSHA256.Hex(), actualParentFp.Hex())
		}
	}
	return nil
}

func (vt *verifyTest) makeVerifier() *Verifier {
	pki := NewGraph()

	joinedIntermediates := strings.Join(vt.Intermediates, "\n")
	intermediateReader := strings.NewReader(joinedIntermediates)
	pki.AppendFromPEM(intermediateReader, false)

	joinedRoots := strings.Join(vt.Roots, "\n")
	rootReader := strings.NewReader(joinedRoots)
	pki.AppendFromPEM(rootReader, true)
	v := NewNSS(pki)
	return v
}

func (vt *verifyTest) makeVerifyOptions() (opts *VerificationOptions) {
	opts = new(VerificationOptions)
	opts.Name = vt.DNSName
	opts.VerifyTime = time.Unix(vt.CurrentTime, 0)

	if vt.CRLSetFn != nil {
		crl, err := vt.CRLSetFn()
		if err != nil {
			panic(err)
		}
		opts.CRLSet = crl
	}
	if vt.OneCRLFn != nil {
		crl, err := vt.OneCRLFn()
		if err != nil {
			panic(err)
		}

		opts.OneCRL = crl
	}

	return opts
}

func (vt *verifyTest) checkVerifyResult(res *VerificationResult) error {
	if err := vt.compareChains(vt.ExpectedChains, res.CurrentChains); err != nil {
		return fmt.Errorf("bad expected chains: %s", err)
	}
	if err := vt.compareChains(vt.ExpiredChains, res.ExpiredChains); err != nil {
		return fmt.Errorf("bad expired chains: %s", err)
	}
	if err := vt.compareChains(vt.NeverChains, res.NeverValidChains); err != nil {
		return fmt.Errorf("bad never chains: %s", err)
	}
	if err := vt.compareParents(vt.ExpectedParents, res.Parents); err != nil {
		return fmt.Errorf("bad parents: %s", err)
	}
	if vt.ExpectHostnameError && res.NameError == nil {
		return fmt.Errorf("expected hostname error, got nil")
	}
	if res.NameError != nil && !vt.ExpectHostnameError {
		return fmt.Errorf("unexpected name error: %s", res.NameError)
	}
	if err := vt.compareParentSPKISubjectToParents(res); err != nil {
		return err
	}

	if vt.InRevocationSet != res.InRevocationSet {
		return fmt.Errorf("unexpected InRevocationSet: %t", res.InRevocationSet)
	}
	return nil
}

var verifyTests = []verifyTest{
	{
		Name:      "PEMLEX3SignedByISRGRootX1-in-CRLSet",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf, // idx=3
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
		CRLSetFn: func() (*google.CRLSet, error) {
			return crlSetIntermediate(data.PEMDAdrianIOSignedByLEX3, []string{
				data.PEMLEX3SignedByDSTRootCAX3, // idx=1
				data.PEMLEX3SignedByISRGRootX1,
			})
		},
		InRevocationSet: true,
	},
	{
		Name:      "PEMLEX3SignedByISRGRootX1-in-CRLSet-clocked",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf, // idx=3
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
		CRLSetFn: func() (*google.CRLSet, error) {
			return crlSetBlocked([]string{data.PEMLEX3SignedByDSTRootCAX3})
		},
		InRevocationSet: true,
	},
	{
		Name:      "PEMLEX3SignedByISRGRootX1-in-OneCRL",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf, // idx=3
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
		OneCRLFn: func() (*mozilla.OneCRL, error) {
			return oneCrlIntermediate(data.PEMDAdrianIOSignedByLEX3, []string{
				data.PEMLEX3SignedByDSTRootCAX3, // idx=1
				data.PEMLEX3SignedByISRGRootX1,
			})
		},
		InRevocationSet: true,
	},
	{
		Name:      "PEMLEX3SignedByISRGRootX1-in-OneCRL-blocked",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf, // idx=3
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
		OneCRLFn: func() (*mozilla.OneCRL, error) {
			return oneCrlBlocked(data.PEMDAdrianIOSignedByLEX3)
		},
		InRevocationSet: true,
	},
	{
		Name:      "le-two-intermediate-dst-root",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf, // idx=3
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
	},
	{
		Name:          "dadrian-missing-intermediate",
		Leaf:          data.PEMDAdrianIOSignedByLEX3,
		Intermediates: nil,
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf,
		},
		CurrentTime:     1501804800, // 2017-08-04T00:00:00
		ExpectedChains:  nil,
		ExpectedParents: nil,
	},
	{
		Name:      "root-only",
		Leaf:      data.PEMDSTRootCAX3SignedBySelf,
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3,
		},
		Roots: []string{
			data.PEMDSTRootCAX3SignedBySelf,
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0},
		},
		ExpiredChains:   nil,
		NeverChains:     nil,
		ExpectedParents: nil,
	},
	{
		Name:      "two-dadrian-le-in-intermediates",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMDAdrianIOSignedByLEX3, // idx=1
			data.PEMLEX3SignedByDSTRootCAX3,
			data.PEMLEX3SignedByISRGRootX1,
			data.PEMISRGRootX1SignedBySelf,
		},
		Roots: []string{
			data.PEMISRGRootX1SignedBySelf, // idx=5
			data.PEMDSTRootCAX3SignedBySelf,
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 2, 6}, {0, 3, 5},
		},
		ExpiredChains:   nil,
		NeverChains:     nil,
		ExpectedParents: []int{2, 3},
	},
	{
		Name:      "two-dadrian-le-no-presented",
		Leaf:      data.PEMDAdrianIOSignedByLEX3, // idx=0
		Presented: nil,
		Intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
			data.PEMISRGRootX1SignedBySelf,
		},
		Roots: []string{
			data.PEMISRGRootX1SignedBySelf, // idx=4
			data.PEMDSTRootCAX3SignedBySelf,
		},
		CurrentTime: 1501804800, // 2017-08-04T00:00:00
		ExpectedChains: [][]int{
			{0, 1, 5}, {0, 2, 4},
		},
		ExpiredChains:   nil,
		NeverChains:     nil,
		ExpectedParents: []int{1, 2},
	},
	{
		Name:      "dod-root-ca-3-in-intermediates",
		Leaf:      data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
		Presented: nil,
		Intermediates: []string{
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2, // idx=1
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA, // idx=5
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA2013,
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA2016,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA, // idx=8
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016,
			data.PEMFederalBridgeCASignedByDoDInteropCA2, // idx=14
			data.PEMFederalBridgeCASignedByFederalBridgeCA2013,
			data.PEMFederalBridgeCASignedByFederalCommonPolicyCA,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524, // idx=17
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424,
			data.PEMFederalBridgeCA2013SignedByDoDInteropCA2,
			data.PEMFederalBridgeCA2013SignedByIdenTrust,
			data.PEMFederalBridgeCA2016SignedByDodInteropCA2, // idx=21
			data.PEMFederalBridgeCA2016SignedByFederalCommonPolicyCA,
		},
		Roots: []string{
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=23
		},
		CurrentTime: 1501545600, // 2017-08-01T00:00:00
		ExpectedChains: [][]int{
			{0, 12, 18, 23},
			{0, 13, 22, 23},
		},
		ExpiredChains: [][]int{
			{0, 8, 15, 17, 23},
			{0, 8, 15, 18, 23},
			{0, 9, 17, 23},
			{0, 9, 18, 23},
			{0, 10, 17, 23},
			{0, 10, 18, 23},
			{0, 11, 17, 23},
			{0, 11, 18, 23},
			{0, 12, 17, 23},
		},
		NeverChains: [][]int{
			{0, 8, 16, 23},
		},
		ExpectedParents: []int{12, 13},
	},
	{
		Name:      "dod-root-ca-3-leaf-no-presented",
		Leaf:      data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
		Presented: nil,
		Intermediates: []string{
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2, // idx=1
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDAdrianIOSignedByLEX3,
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA, // idx=5
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA2013,
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA2016,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA, // idx=8
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016,
			data.PEMFederalBridgeCASignedByDoDInteropCA2, // idx=14
			data.PEMFederalBridgeCASignedByFederalBridgeCA2013,
			data.PEMFederalBridgeCASignedByFederalCommonPolicyCA,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524, // idx=17
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424,
			data.PEMFederalBridgeCA2013SignedByDoDInteropCA2,
			data.PEMFederalBridgeCA2013SignedByIdenTrust,
			data.PEMFederalBridgeCA2016SignedByDodInteropCA2, // idx=21
			data.PEMFederalBridgeCA2016SignedByFederalCommonPolicyCA,
		},
		Roots: []string{
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=23
		},
		CurrentTime: 1501545600, // 2017-08-01T00:00:00
		ExpectedChains: [][]int{
			{0, 12, 18, 23},
			{0, 13, 22, 23},
		},
		ExpiredChains: [][]int{
			{0, 8, 15, 17, 23},
			{0, 8, 15, 18, 23},
			{0, 9, 17, 23},
			{0, 9, 18, 23},
			{0, 10, 17, 23},
			{0, 10, 18, 23},
			{0, 11, 17, 23},
			{0, 11, 18, 23},
			{0, 12, 17, 23},
		},
		NeverChains: [][]int{
			{0, 8, 16, 23},
		},
		ExpectedParents: []int{12, 13},
	},
	{
		Name: "google-no-presented-chain",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime: 1395785200,
		DNSName:     "www.google.com",
		ExpectedChains: [][]int{
			{0, 1, 2},
		},
		ExpectedParents: []int{1},
		CRLSetFn:        loadCrlSet6375,
		OneCRLFn:        loadTestOneCRL,
	},
	{
		Name: "google-mixed-case",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime: 1395785200,
		DNSName:     "www.google.com",
		ExpectedChains: [][]int{
			{0, 1, 2},
		},
		ExpectedParents: []int{1},
		CRLSetFn:        loadCrlSet6375,
		OneCRLFn:        loadTestOneCRL,
	},
	{
		Name: "google-not-yet-valid",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime:    1,
		DNSName:        "www.google.com",
		ExpectedChains: nil,
		ExpiredChains: [][]int{
			{0, 1, 2},
		},
		ExpectedParents: []int{1},
	},
	{
		Name: "google-expired",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime:    2000000000,
		DNSName:        "www.google.com",
		ExpectedChains: nil,
		ExpiredChains: [][]int{
			{0, 1, 2},
		},
		ExpectedParents: []int{1},
		CRLSetFn:        loadCrlSet6375,
		OneCRLFn:        loadTestOneCRL,
	},
	{
		Name: "google-name-mismatch",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime: 1395785200,
		DNSName:     "www.example.com",
		ExpectedChains: [][]int{
			{0, 1, 2},
		},
		ExpectedParents:     []int{1},
		ExpectHostnameError: true,
	},
	{
		Name:          "google-missing-intermediate",
		Leaf:          data.PEMGoogleSignedByGIAG2,
		Intermediates: nil,
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime:     1395785200,
		ExpectedChains:  nil,
		ExpectedParents: nil,
	},
	{
		Name: "google-with-unrelated-intermediate",
		Leaf: data.PEMGoogleSignedByGIAG2,
		Intermediates: []string{
			data.PEMGIAG2SignedByGeoTrust,
			data.PEMDAdrianIOSignedByLEX3,
		},
		Roots: []string{
			data.PEMGeoTrustSignedBySelf,
		},
		CurrentTime: 1395785200,
		DNSName:     "www.google.com",
		ExpectedChains: [][]int{
			{0, 1, 3},
		},
		ExpectedParents: []int{1},
	},
}

func TestVerify(t *testing.T) {
	for _, test := range verifyTests {
		test.parseSelf()
		v := test.makeVerifier()
		opts := test.makeVerifyOptions()
		verifyResult := v.Verify(test.parsedLeaf(), *opts)
		if err := test.checkVerifyResult(verifyResult); err != nil {
			t.Errorf("%s: %s", test.Name, err)
		}
	}
}

func loadCRLSet(data string) (*google.CRLSet, error) {
	crlSetFile, err := os.Open(data)
	if err != nil {
		return nil, err
	}
	defer crlSetFile.Close()

	crlSetBytes, err := ioutil.ReadAll(crlSetFile)
	if err != nil {
		return nil, err
	}

	crlset, err := google.Parse(crlSetBytes, "6375")
	if err != nil {
		return nil, err
	}
	return crlset, nil
}

func loadOneCRL(data string) (*mozilla.OneCRL, error) {
	oneCRLFile, err := os.Open(data)
	if err != nil {
		return nil, err
	}
	defer oneCRLFile.Close()
	oneCRLBytes, err := ioutil.ReadAll(oneCRLFile)
	if err != nil {
		return nil, err
	}

	onecrl, err := mozilla.Parse(oneCRLBytes)
	if err != nil {
		return nil, err
	}
	return onecrl, nil
}

func loadCrlSet6375() (*google.CRLSet, error) {
	return loadCRLSet("testdata/crl-set-6375")
}

func loadTestOneCRL() (*mozilla.OneCRL, error) {
	return loadOneCRL("testdata/test_onecrl.json")
}

func crlSetIntermediate(leafPEM string, intermediatesPEM []string) (*google.CRLSet, error) {
	crl := &google.CRLSet{
		IssuerLists: make(map[string]*google.IssuerList),
	}

	leaf := loadPEM(leafPEM)
	for _, ca := range loadPEMs(intermediatesPEM) {
		if ca.Subject.CommonName == leaf.Issuer.CommonName {
			spki := hex.EncodeToString(ca.SPKIFingerprint)

			entries := &google.IssuerList{
				SPKIHash: spki,
				Entries: []*google.Entry{
					{SerialNumber: leaf.SerialNumber},
				},
			}

			crl.IssuerLists[spki] = entries
		}
	}
	return crl, nil
}

func crlSetBlocked(intermediatesPEM []string) (*google.CRLSet, error) {
	crl := &google.CRLSet{
		IssuerLists:  make(map[string]*google.IssuerList),
		BlockedSPKIs: make([]string, 0),
	}

	for _, ca := range loadPEMs(intermediatesPEM) {
		spki := hex.EncodeToString(ca.SPKIFingerprint)
		crl.BlockedSPKIs = append(crl.BlockedSPKIs, spki)

	}
	return crl, nil
}

func oneCrlIntermediate(leafPEM string, intermediatesPEM []string) (*mozilla.OneCRL, error) {
	crl := &mozilla.OneCRL{
		IssuerLists: make(map[string]*mozilla.IssuerList),
	}

	leaf := loadPEM(leafPEM)
	for _, ca := range loadPEMs(intermediatesPEM) {
		if ca.Subject.CommonName == leaf.Issuer.CommonName {
			entries := &mozilla.IssuerList{
				Issuer: &ca.Subject,
				Entries: []*mozilla.Entry{
					{
						Issuer:       &ca.Subject,
						SerialNumber: leaf.SerialNumber,
					},
				},
			}

			crl.IssuerLists[leaf.Issuer.String()] = entries
		}
	}
	return crl, nil
}

func oneCrlBlocked(leafPEM string) (*mozilla.OneCRL, error) {
	crl := &mozilla.OneCRL{
		IssuerLists: make(map[string]*mozilla.IssuerList),
		Blocked:     make([]*mozilla.SubjectAndPublicKey, 0),
	}

	leaf := loadPEM(leafPEM)

	pubKeyData, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	hash := sha256.Sum256(pubKeyData)

	spk := &mozilla.SubjectAndPublicKey{
		RawSubject: leaf.RawSubject,
		Subject:    &leaf.Subject,
		PubKeyHash: hash[:],
	}

	crl.Blocked = append(crl.Blocked, spk)
	return crl, nil
}
