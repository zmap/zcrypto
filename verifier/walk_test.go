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

import "testing"

func TestWalk(t *testing.T) {
	type empty struct{}

	for _, test := range verifyTests {
		g := NewGraph()
		test.parseSelf()

		// Add the presented chain
		// TODO

		for _, c := range test.parsedIntermediates() {
			g.AddCert(c)
		}
		for _, c := range test.parsedRoots() {
			g.AddRoot(c)
		}

		// See what chains we got
		actualChains := g.WalkChains(test.parsedLeaf())
		if err := test.compareChains(test.unionAllExpected(), actualChains); err != nil {
			t.Errorf("%s: %s", test.Name, err)
		}
	}
}
