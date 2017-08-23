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
	"strings"
	"testing"

	"github.com/zmap/zcrypto/x509"

	data "github.com/zmap/zcrypto/data/test/certificates"
)

type edgeIdx struct {
	issuer, child, cert int
}

type graphTest struct {
	name          string
	certificates  []string
	expectedNodes []string
	expectedEdges []edgeIdx
}

var graphTests = []graphTest{
	{
		name:          "one-certificate",
		certificates:  []string{data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3},
		expectedEdges: []edgeIdx{{-1, 0, 0}},
	},
	{
		name:          "child-parent",
		certificates:  []string{data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655, data.PEMDoDInteropCA2SignedByFederalBridgeCA2016},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3, data.HexSPKISubjectFingerprintDoDInteropCA2},
		expectedEdges: []edgeIdx{{1, 0, 0}, {-1, 1, 1}},
	},
	{
		name:          "parent-child",
		certificates:  []string{data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3, data.HexSPKISubjectFingerprintDoDInteropCA2},
		expectedEdges: []edgeIdx{{1, 0, 1}, {-1, 1, 0}},
	},
	{
		name:          "two-unrelated",
		certificates:  []string{data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, data.PEMDAdrianIOSignedByLEX3},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDInteropCA2, data.HexSPKISubjectFingerprintDAdrianIO},
		expectedEdges: []edgeIdx{{-1, 0, 0}, {-1, 1, 1}},
	},
	{
		name:          "self-signed",
		certificates:  []string{data.PEMDoDRootCA3SignedBySelf},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3},
		expectedEdges: []edgeIdx{{0, 0, 0}},
	},
	{
		name:          "dod-root-ca-3-no-issuers",
		certificates:  []string{data.PEMDoDRootCA3SignedBySelf, data.PEMDoDRootCA3SignedByCCEBInteropRootCA2, data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655, data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3},
		expectedEdges: []edgeIdx{{0, 0, 0}, {-1, 0, 1}, {-1, 0, 2}, {-1, 0, 3}},
	},
	{
		name: "dod-root-ca-3-interop-issued-by-bridge-16",
		certificates: []string{
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, // issuer (idx=4)
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintDoDRootCA3,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
		},
		expectedEdges: []edgeIdx{{0, 0, 0}, {-1, 0, 1}, {1, 0, 2}, {1, 0, 3}, {-1, 1, 4}},
	},
	{
		name: "dod-root-ca-3-interop-issued-by-bridge-16-reversed",
		certificates: []string{
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, // issuer (idx=0)
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintDoDRootCA3,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
		},
		expectedEdges: []edgeIdx{{0, 0, 1}, {-1, 0, 2}, {1, 0, 3}, {1, 0, 4}, {-1, 1, 0}},
	},
	{
		name: "dod-root-ca-3-interop-ca-2",
		certificates: []string{
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, // issuer (idx=4),
			data.PEMDoDInteropCA2SignedByFederalBridgeCA,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644, // (idx=9)
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintDoDRootCA3,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
		},
		expectedEdges: []edgeIdx{
			{0, 0, 0},
			{-1, 0, 1},
			{1, 0, 2},
			{1, 0, 3},
			{-1, 1, 4},
			{-1, 1, 5},
			{-1, 1, 6},
			{-1, 1, 7},
			{-1, 1, 8},
			{-1, 1, 9},
		},
	},
	{
		name: "bridge-ca-13",
		certificates: []string{
			data.PEMFederalBridgeCA2013SignedByIdenTrust,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424,
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintFederalBridgeCA2013,
		},
		expectedEdges: []edgeIdx{
			{-1, 0, 0},
			{-1, 0, 1},
			{-1, 0, 2},
		},
	},
	{
		name: "bridge-ca-13-dod-root-ca-3-dod-interop-join",
		certificates: []string{
			data.PEMFederalBridgeCA2013SignedByIdenTrust,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424,
			data.PEMDoDRootCA3SignedBySelf, // idx=3
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, // idx=7
			data.PEMDoDInteropCA2SignedByFederalBridgeCA,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial906,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8225,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial8844,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2013Serial9644, // idx=12
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintDoDRootCA3,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
			data.HexSPKISubjectFingerprintFederalBridgeCA2013,
		},
		expectedEdges: []edgeIdx{
			{-1, 2, 0},
			{-1, 2, 1},
			{-1, 2, 2},
			{0, 0, 3},
			{-1, 0, 4},
			{1, 0, 5},
			{1, 0, 6},
			{-1, 1, 7},
			{-1, 1, 8},
			{2, 1, 9},
			{2, 1, 10},
			{2, 1, 11},
			{2, 1, 12},
		},
	},
	{
		name: "bridge-ca-2016-loop-with-interop",
		certificates: []string{
			data.PEMFederalBridgeCA2016SignedByDodInteropCA2,
			data.PEMDoDInteropCA2SignedByFederalBridgeCA2016,
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintFederalBridgeCA2016,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
		},
		expectedEdges: []edgeIdx{
			{1, 0, 0},
			{0, 1, 1},
		},
	},
	{
		name: "all-bridge-ca-joined-by-common-policy-self-signed",
		certificates: []string{
			data.PEMFederalBridgeCA2016SignedByFederalCommonPolicyCA,
			data.PEMFederalBridgeCASignedByFederalCommonPolicyCA,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial5524,
			data.PEMFederalBridgeCA2013SignedByCommonPolicyCASerial11424,
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=4
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintFederalBridgeCA,
			data.HexSPKISubjectFingerprintFederalBridgeCA2013,
			data.HexSPKISubjectFingerprintFederalBridgeCA2016,
			data.HexSPKISubjectFingerprintFederalCommonPolicyCA, // idx=3
		},
		expectedEdges: []edgeIdx{
			{3, 2, 0},
			{3, 0, 1},
			{3, 1, 2},
			{3, 1, 3},
			{3, 3, 4},
		},
	},
	{
		name: "fpki",
		certificates: []string{
			data.PEMDoDRootCA3SignedByCCEBInteropRootCA2,
			data.PEMDoDRootCA3SignedBySelf,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655,
			data.PEMDoDRootCA3SignedByDoDInteropCA2Serial748,
			data.PEMFederalCommonPolicyCASignedBySelf, // idx=4
			data.PEMFederalCommonPolicyCASignedByFederalBridgeCA,
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
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintDoDRootCA3,
			data.HexSPKISubjectFingerprintDoDInteropCA2,
			data.HexSPKISubjectFingerprintFederalBridgeCA, //idx=2
			data.HexSPKISubjectFingerprintFederalBridgeCA2013,
			data.HexSPKISubjectFingerprintFederalBridgeCA2016,
			data.HexSPKISubjectFingerprintFederalCommonPolicyCA, //idx=5
		},
		expectedEdges: []edgeIdx{
			{-1, 0, 0},
			{0, 0, 1},
			{1, 0, 2},
			{1, 0, 3},
			{5, 5, 4},
			{2, 5, 5},
			{3, 5, 6},
			{4, 5, 7},
			{2, 1, 8},
			{3, 1, 9},
			{3, 1, 10},
			{3, 1, 11},
			{3, 1, 12},
			{4, 1, 13},
			{1, 2, 14},
			{3, 2, 15},
			{5, 2, 16},
			{5, 3, 17},
			{5, 3, 18},
			{1, 3, 19},
			{-1, 3, 20},
			{1, 4, 21},
			{5, 4, 22},
		},
	},
	{
		name: "wuerzburg",
		certificates: []string{
			data.PEMSBHome6WuerzburgSignedByUNIWUCAG01,
			data.PEMUNIWUCAG01SignedByDFNVerin,
		},
		expectedNodes: []string{
			data.HexSPKISubjectFingerprintUNIWUCAG01,
			data.HexSPKISubjectFingerprintSBHome6Wuerzburg,
		},
		expectedEdges: []edgeIdx{
			{0, 1, 0},
			{-1, 0, 1},
		},
	},
	{
		name: "empty", // this shouldn't panic
	},
}

func TestGraphAddOneCert(t *testing.T) {
	c := loadPEM(data.PEMDoDRootCA3SignedByDoDInteropCA2Serial655)
	g := NewGraph()
	g.AddCert(c)
	nodes := g.Nodes()
	if len(nodes) != 1 {
		t.Errorf("expected len(nodes) = 1, got %d", len(nodes))
	}
	edge := g.FindEdge(c.FingerprintSHA256)
	if edge == nil {
		t.Error("did not find edge")
		t.FailNow()
	}
	if edge.child == nil {
		t.Error("child should never be nil")
	}
	if edge.issuer != nil {
		t.Error("issuer should not be set, only one certificate was added")
	}
}

func TestGraph(t *testing.T) {
	for _, test := range graphTests {
		g := NewGraph()
		var certificates []*x509.Certificate
		// Add all the certificates to the graph
		for _, pem := range test.certificates {
			c := loadPEM(pem)
			certificates = append(certificates, c)
			g.AddCert(c)
		}

		var expectedNodeFingerprints []x509.CertificateFingerprint
		for _, hexfp := range test.expectedNodes {
			fp, err := hex.DecodeString(hexfp)
			if err != nil {
				t.Errorf("%s: unabled to decode hex spki_subject_fingerprint %s", test.name, hexfp)
				t.FailNow()
			}
			expectedNodeFingerprints = append(expectedNodeFingerprints, fp)
		}

		// Ensure each node exists
		nodes := g.Nodes()
		if len(nodes) != len(test.expectedNodes) {
			t.Errorf("%s: expected %d nodes, got %d", test.name, len(test.expectedNodes), len(nodes))
		}
		for _, fp := range expectedNodeFingerprints {
			node := g.FindNode(fp)
			if node == nil {
				t.Errorf("%s: missing expected node %s", test.name, fp.Hex())
			}
		}

		// Ensure each certificate has an edge
		edges := g.Edges()
		if len(test.expectedEdges) != len(edges) {
			t.Errorf("%s: expected %d edges, got %d", test.name, len(test.expectedEdges), len(edges))
		}
		for certIdx, c := range certificates {
			edge := g.FindEdge(c.FingerprintSHA256)
			if edge == nil {
				t.Errorf("%s: certificate #%d had no edge (%s)", test.name, certIdx, c.FingerprintSHA256.Hex())
			}
		}
		for _, indicies := range test.expectedEdges {
			c := certificates[indicies.cert]
			edge := g.FindEdge(c.FingerprintSHA256)
			expectedChildFP := expectedNodeFingerprints[indicies.child]
			actualChildFP := edge.child.SubjectAndKey.Fingerprint
			if !expectedChildFP.Equal(actualChildFP) {
				t.Errorf("%s: expected edge for certificate %s to have subject node %s, got %s", test.name, c.FingerprintSHA256.Hex(), expectedChildFP.Hex(), actualChildFP.Hex())
			}
			if indicies.issuer < 0 {
				if edge.issuer != nil {
					t.Errorf("%s: expected edge for certificate %s to have nil issuer, got %s", test.name, c.FingerprintSHA256.Hex(), edge.issuer.SubjectAndKey.Fingerprint.Hex())
				}
				continue
			}
			expectedIssuerFP := expectedNodeFingerprints[indicies.issuer]
			if edge.issuer == nil {
				t.Errorf("%s: expected edge for certificate %s to have issuer %s, got nil", test.name, c.FingerprintSHA256.Hex(), expectedIssuerFP.Hex())
				continue
			}
			actualIssuerFP := edge.issuer.SubjectAndKey.Fingerprint
			if !expectedIssuerFP.Equal(actualIssuerFP) {
				t.Errorf("%s: expected edge for certificate %s to have issuer %s, got %s", test.name, c.FingerprintSHA256.Hex(), expectedIssuerFP.Hex(), actualIssuerFP.Hex())
			}
		}

	}
}

func TestAppendFromPEM(t *testing.T) {
	for _, test := range graphTests {
		g := NewGraph()
		joined := strings.Join(test.certificates, "\n")
		r := strings.NewReader(joined)
		n := g.AppendFromPEM(r, false)
		if len(test.certificates) != n {
			t.Errorf("%s: expected size %d, got %d", test.name, len(test.certificates), n)
		}
	}
}
