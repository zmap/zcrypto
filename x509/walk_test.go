// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/hex"
	"strings"
	"testing"

	data "github.com/zmap/zcrypto/data/test/certificates"
)

func prettyChainID(chainID string) string {
	var parts []string
	for i := 0; i < len(chainID); i += 256 / 8 {
		sub := chainID[i : i+256/8]
		parts = append(parts, hex.EncodeToString([]byte(sub)))
	}
	return strings.Join(parts, "|")
}

type walkTest struct {
	name                            string
	start                           string
	presented, intermediates, roots []string
	expectedChains                  [][]int
}

var walkTests = []walkTest{
	{
		name:  "root",
		start: data.PEMDSTRootCAX3SignedBySelf,
		intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3,
		},
		roots: []string{
			data.PEMDSTRootCAX3SignedBySelf,
		},
		expectedChains: [][]int{
			[]int{0},
		},
	},
	{
		name:  "two-dadrian-le",
		start: data.PEMDAdrianIOSignedByLEX3, // idx=0
		intermediates: []string{
			data.PEMDAdrianIOSignedByLEX3, // idx=1
			data.PEMLEX3SignedByDSTRootCAX3,
			data.PEMLEX3SignedByISRGRootX1,
			data.PEMISRGRootX1SignedBySelf,
		},
		roots: []string{
			data.PEMISRGRootX1SignedBySelf, // idx=5
			data.PEMDSTRootCAX3SignedBySelf,
		},
		expectedChains: [][]int{
			[]int{0, 2, 6}, []int{0, 3, 5},
		},
	},
	{
		name:  "two-dadrian-le-no-leaf-in-graph",
		start: data.PEMDAdrianIOSignedByLEX3, // idx=0
		intermediates: []string{
			data.PEMLEX3SignedByDSTRootCAX3, // idx=1
			data.PEMLEX3SignedByISRGRootX1,
			data.PEMISRGRootX1SignedBySelf,
		},
		roots: []string{
			data.PEMISRGRootX1SignedBySelf, // idx=4
			data.PEMDSTRootCAX3SignedBySelf,
		},
		expectedChains: [][]int{
			[]int{0, 1, 5}, []int{0, 2, 4},
		},
	},
	{
		name:  "dod-root-ca-3",
		start: data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
		intermediates: []string{
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
		roots: []string{
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=23
		},
		expectedChains: [][]int{
			[]int{0, 8, 16, 23},
			[]int{0, 8, 15, 17, 23},
			[]int{0, 8, 15, 18, 23},
			[]int{0, 9, 17, 23},
			[]int{0, 9, 18, 23},
			[]int{0, 10, 17, 23},
			[]int{0, 10, 18, 23},
			[]int{0, 11, 17, 23},
			[]int{0, 11, 18, 23},
			[]int{0, 12, 17, 23},
			[]int{0, 12, 18, 23},
			[]int{0, 13, 22, 23},
		},
	},
	{
		name:  "dod-root-ca-3-leaf-not-in-graph",
		start: data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
		intermediates: []string{
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
		roots: []string{
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=23
		},
		expectedChains: [][]int{
			[]int{0, 8, 16, 23},
			[]int{0, 8, 15, 17, 23},
			[]int{0, 8, 15, 18, 23},
			[]int{0, 9, 17, 23},
			[]int{0, 9, 18, 23},
			[]int{0, 10, 17, 23},
			[]int{0, 10, 18, 23},
			[]int{0, 11, 17, 23},
			[]int{0, 11, 18, 23},
			[]int{0, 12, 17, 23},
			[]int{0, 12, 18, 23},
			[]int{0, 13, 22, 23},
		},
	},
}

func TestWalk(t *testing.T) {
	type empty struct{}

	for _, test := range walkTests {
		g := NewGraph()

		// All certificates
		var certificates []*Certificate

		start, err := certificateFromPEM(test.start)
		if err != nil {
			t.Errorf("%s: could not parse start certificate", test.name)
			continue
		}

		// Add the presented chain
		var presentedChain []*Certificate
		// TODO

		// Add all the intermediates to the graph
		var intermediates []*Certificate
		for certIdx, pem := range test.intermediates {
			c, err := certificateFromPEM(pem)
			if err != nil {
				t.Errorf("%s: could not parse certificate #%d", test.name, certIdx)
				t.FailNow()
			}
			g.AddCert(c)
			intermediates = append(intermediates, c)
		}

		// Add all the roots to the graph
		var roots []*Certificate
		for rootIdx, pem := range test.roots {
			c, err := certificateFromPEM(pem)
			if err != nil {
				t.Errorf("%s: could not parse root certificate #%d", test.name, rootIdx)
				t.FailNow()
			}
			roots = append(roots, c)
			g.AddRoot(c)
		}

		// Make a big list of all the certs to use for expected chains
		certificates = append(certificates, start)
		certificates = append(certificates, presentedChain...)
		certificates = append(certificates, intermediates...)
		certificates = append(certificates, roots...)

		// Read the expected chains from the test
		expectedChainIDs := make(map[string]empty)
		for _, chainIndicies := range test.expectedChains {
			var chain CertificateChain
			for _, certIdx := range chainIndicies {
				c := certificates[certIdx]
				chain = append(chain, c)
			}
			expectedChainIDs[chain.chainID()] = empty{}
		}

		// See what chains we got
		actualChains := g.WalkChains(start)
		actualChainIDs := make(map[string]empty)
		for _, chain := range actualChains {
			actualChainIDs[chain.chainID()] = empty{}
		}

		// Check to make sure they're the same
		if len(expectedChainIDs) != len(actualChainIDs) {
			t.Errorf("%s: expected %d chains, got %d", test.name, len(expectedChainIDs), len(actualChainIDs))
		}

		for expectedChainID := range expectedChainIDs {
			_, ok := actualChainIDs[expectedChainID]
			if !ok {
				t.Errorf("%s: missing chain %s", test.name, prettyChainID(expectedChainID))
			}
		}
	}
}
