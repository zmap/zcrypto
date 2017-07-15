// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/hex"
	"testing"

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
		certificates:  []string{data.PEMDoDRootCA3SignedByDoDInteropCA2},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3},
		expectedEdges: []edgeIdx{{-1, 0, 0}},
	},
	{
		name:          "child-parent",
		certificates:  []string{data.PEMDoDRootCA3SignedByDoDInteropCA2, data.PEMDoDInteropCA2SignedByFederalBridgeCA2016},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3, data.HexSPKISubjectFingerprintDoDInteropCA2},
		expectedEdges: []edgeIdx{{1, 0, 0}, {-1, 1, 1}},
	},
	{
		name:          "parent-child",
		certificates:  []string{data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, data.PEMDoDRootCA3SignedByDoDInteropCA2},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDRootCA3, data.HexSPKISubjectFingerprintDoDInteropCA2},
		expectedEdges: []edgeIdx{{1, 0, 1}, {-1, 1, 0}},
	},
	{
		name:          "two-unrelated",
		certificates:  []string{data.PEMDoDInteropCA2SignedByFederalBridgeCA2016, data.PEMDAdrianIOSignedByLEX3},
		expectedNodes: []string{data.HexSPKISubjectFingerprintDoDInteropCA2, data.HexSPKISubjectFingerprintDAdrianIO},
		expectedEdges: []edgeIdx{{-1, 0, 0}, {-1, 1, 1}},
	},
}

func TestGraphAddOneCert(t *testing.T) {
	c, _ := certificateFromPEM(data.PEMDoDRootCA3SignedByDoDInteropCA2)
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
		var certificates []*Certificate
		// Add all the certificates to the graph
		for certIdx, pem := range test.certificates {
			c, err := certificateFromPEM(pem)
			if err != nil {
				t.Errorf("%s: could not parse certificate #%d", test.name, certIdx)
				t.FailNow()
			}
			certificates = append(certificates, c)
			g.AddCert(c)
		}

		var expectedNodeFingerprints []CertificateFingerprint
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
			}
			actualIssuerFP := edge.issuer.SubjectAndKey.Fingerprint
			if !expectedIssuerFP.Equal(actualIssuerFP) {
				t.Errorf("%s: expected edge for certificate %s to have issuer %s, got %s", test.name, c.FingerprintSHA256.Hex(), expectedIssuerFP.Hex(), actualIssuerFP.Hex())
			}
		}

	}
}
