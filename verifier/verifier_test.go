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
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/data/test/chains"
	"github.com/zmap/zcrypto/x509"
)

func initVerifierFromTest(test *chains.VerifyTest) *Verifier {
	pki := x509.NewGraph()

	joinedIntermediates := strings.Join(test.Intermediates, "\n")
	intermediateReader := strings.NewReader(joinedIntermediates)
	pki.AppendFromPEM(intermediateReader, false)

	joinedRoots := strings.Join(test.Roots, "\n")
	rootReader := strings.NewReader(joinedRoots)
	pki.AppendFromPEM(rootReader, true)
	v := NewNSS(pki)
	return v
}

func optsFromTest(test *chains.VerifyTest) (opts *VerificationOptions) {
	opts = new(VerificationOptions)
	opts.Name = test.DNSName
	opts.VerifyTime = time.Unix(test.CurrentTime, 0)
	return opts
}

func checkVerifyResult(test *chains.VerifyTest, res *VerificationResult) error {
	if err := test.CompareChains(test.ExpectedChains, res.CurrentChains); err != nil {
		return err
	}
	if err := test.CompareParents(test.ExpectedParents, res.Parents); err != nil {
		return err
	}
	return nil
}

func TestVerify(t *testing.T) {
	for _, test := range chains.VerifyTests {
		test.ParseSelf()
		v := initVerifierFromTest(&test)
		opts := optsFromTest(&test)
		verifyResult := v.Verify(test.ParsedLeaf(), *opts)
		if err := checkVerifyResult(&test, verifyResult); err != nil {
			t.Errorf("%s: bad result: %s", test.Name, err)
		}
	}
}
