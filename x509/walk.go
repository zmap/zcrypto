// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

type WalkOptions struct {
	ChannelSize int
}

func (g *Graph) WalkChainsAsync(c *Certificate, opt WalkOptions) chan CertificateChain {
	if opt.ChannelSize <= 0 {
		opt.ChannelSize = 4
	}
	out := make(chan CertificateChain, opt.ChannelSize)
	start := g.FindEdge(c.FingerprintSHA256)
	if start == nil {
		start = new(GraphEdge)
		start.Certificate = c
		parentCandidates := g.nodesBySubject[string(c.RawIssuer)]
		for _, candidate := range parentCandidates {
			identity := candidate.SubjectAndKey
			if err := checkSignatureFromKey(identity.PublicKey, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
				continue
			}
			start.issuer = candidate
			break
		}
	}
	go g.walkFromEdgeToRoot(start, out)
	return out
}

func (g *Graph) WalkChains(c *Certificate) (out []CertificateChain) {
	chainChan := g.WalkChainsAsync(c, WalkOptions{})
	for chain := range chainChan {
		out = append(out, chain)
	}
	return
}

func (g *Graph) walkFromEdgeToRoot(start *GraphEdge, out chan CertificateChain) {
	soFar := CertificateChain{start.Certificate}
	g.continueWalking(out, start, start.issuer, soFar, start)
	close(out)
	return
}

func (g *Graph) continueWalking(found chan CertificateChain, start *GraphEdge, current *GraphNode, soFar CertificateChain, lastEdge *GraphEdge) {
	// If the chain ends at a root certificate, send the chain through the out channel.
	if lastEdge.root {
		found <- soFar
		return
	}

	if current == nil {
		return
	}

	// If we've traveled too far, just stop.
	if len(soFar) >= maxIntermediateCount {
		return
	}

	// Try to find the next node. Get edges that all go to the same node.
	for skfp, edgeSet := range current.parentsBySubjectAndKey {
		targetNode := g.nodesBySubjectAndKey[skfp]

		// Check to see if these edges are taking us to something already in the
		// chain. If the node's SubjectAndKey is already in the chain, don't bother.
		if targetNode != nil {
			if soFar.SubjectAndKeyInChain(targetNode.SubjectAndKey) {
				continue
			}
		}

		// We're not going to revisit anything now. On the off chance the targetNode
		// was nil, we also aren't doing a duplicate visit, because if we were, the
		// edge would not be dangling.
		for _, edge := range edgeSet.edges {
			nextSoFar := soFar.appendToFreshChain(edge.Certificate)
			g.continueWalking(found, start, edge.issuer, nextSoFar, edge)
		}

	}
	return
}
