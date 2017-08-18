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
	"fmt"
	"strings"
	"testing"
	"time"

	data "github.com/zmap/zcrypto/data/test/certificates"
)

func initVerifierFromTest(test *verifyTest) *Verifier {
	pki := NewGraph()

	joinedIntermediates := strings.Join(test.Intermediates, "\n")
	intermediateReader := strings.NewReader(joinedIntermediates)
	pki.AppendFromPEM(intermediateReader, false)

	joinedRoots := strings.Join(test.Roots, "\n")
	rootReader := strings.NewReader(joinedRoots)
	pki.AppendFromPEM(rootReader, true)
	v := NewNSS(pki)
	return v
}

func (vt *verifyTest) makeVerifyOptions() (opts *VerificationOptions) {
	opts = new(VerificationOptions)
	opts.Name = vt.DNSName
	opts.VerifyTime = time.Unix(vt.CurrentTime, 0)
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
	return nil
}

var verifyTests = []verifyTest{
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
		ExpiredChains:   nil,
		NeverChains:     nil,
		ExpectedParents: []int{1},
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
			[]int{0},
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
			[]int{0, 2, 6}, []int{0, 3, 5},
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
			[]int{0, 1, 5}, []int{0, 2, 4},
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
			[]int{0, 12, 18, 23},
			[]int{0, 13, 22, 23},
		},
		ExpiredChains: [][]int{
			[]int{0, 8, 15, 17, 23},
			[]int{0, 8, 15, 18, 23},
			[]int{0, 9, 17, 23},
			[]int{0, 9, 18, 23},
			[]int{0, 10, 17, 23},
			[]int{0, 10, 18, 23},
			[]int{0, 11, 17, 23},
			[]int{0, 11, 18, 23},
			[]int{0, 12, 17, 23},
		},
		NeverChains: [][]int{
			[]int{0, 8, 16, 23},
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
			[]int{0, 12, 18, 23},
			[]int{0, 13, 22, 23},
		},
		ExpiredChains: [][]int{
			[]int{0, 8, 15, 17, 23},
			[]int{0, 8, 15, 18, 23},
			[]int{0, 9, 17, 23},
			[]int{0, 9, 18, 23},
			[]int{0, 10, 17, 23},
			[]int{0, 10, 18, 23},
			[]int{0, 11, 17, 23},
			[]int{0, 11, 18, 23},
			[]int{0, 12, 17, 23},
		},
		NeverChains: [][]int{
			[]int{0, 8, 16, 23},
		},
		ExpectedParents: []int{12, 13},
	},
}

func TestVerify(t *testing.T) {
	for _, test := range verifyTests {
		test.parseSelf()
		v := initVerifierFromTest(&test)
		opts := test.makeVerifyOptions()
		verifyResult := v.Verify(test.parsedLeaf(), *opts)
		if err := test.checkVerifyResult(verifyResult); err != nil {
			t.Errorf("%s: %s", test.Name, err)
		}
	}
}
