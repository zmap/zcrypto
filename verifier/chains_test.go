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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

func loadPEMs(pems []string) (out []*x509.Certificate) {
	for _, s := range pems {
		c, _ := certificateFromPEM(s)
		out = append(out, c)
	}
	return
}

func certificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func getChainID(chain x509.CertificateChain) string {
	parts := make([]string, 0, len(chain))
	for _, c := range chain {
		hexHash := hex.EncodeToString(c.FingerprintSHA256)
		parts = append(parts, hexHash)
	}
	return strings.Join(parts, "|")
}

type ChainError struct {
	Extra, Missing []string
}

func (e *ChainError) Error() string {
	out := fmt.Sprintf("missing chains: %v, extra chains: %v", e.Missing, e.Extra)
	return out
}

type ParentError struct {
	Extra, Missing []string
}

func (e *ParentError) Error() string {
	out := fmt.Sprintf("missing parents: %v, extra parents: %v", e.Missing, e.Extra)
	return out
}

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

	certificates                    []*x509.Certificate
	leaf                            *x509.Certificate
	presented, intermediates, roots []*x509.Certificate
}

func (vt *verifyTest) parseSelf() {
	vt.leaf, _ = certificateFromPEM(vt.Leaf)
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

func (vt *verifyTest) compareChains(expected [][]int, actual []x509.CertificateChain) *ChainError {
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
		err := ChainError{
			Missing: missing,
			Extra:   extra,
		}
		return &err
	}
	return nil
}

func (vt *verifyTest) compareParents(expected []int, actual []*x509.Certificate) *ParentError {
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
		err := ParentError{
			Missing: missing,
			Extra:   extra,
		}
		return &err
	}
	return nil
}
