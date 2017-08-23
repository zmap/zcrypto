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

import "github.com/zmap/zcrypto/x509"

const maxIntermediateCount = 9

// WalkOptions contains options for the Graph.Walk* functions. It's a structure
// since anything related to verification inevitably results in a large number
// of arguments.
type WalkOptions struct {
	ChannelSize int
}

// WalkChainsAsync performs a depth-first walk of g, starting at c, to any root
// edges. It returns all non-looping paths from c to a root. WalkChainsAsync
// immediately returns a channel. It sends any chains it finds through the
// channel, and closes it once all paths have been found. If the channel does
// not get consumed, this function may block indefinitely.
func (g *Graph) WalkChainsAsync(c *x509.Certificate, opt WalkOptions) chan x509.CertificateChain {
	if opt.ChannelSize <= 0 {
		opt.ChannelSize = 4
	}
	out := make(chan x509.CertificateChain, opt.ChannelSize)
	start := g.FindEdge(c.FingerprintSHA256)
	if start == nil {
		start = new(GraphEdge)
		start.Certificate = c
		parentCandidates := g.nodesBySubject[string(c.RawIssuer)]
		for _, candidate := range parentCandidates {
			identity := candidate.SubjectAndKey
			if err := x509.CheckSignatureFromKey(identity.PublicKey, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
				continue
			}
			start.issuer = candidate
			break
		}
	}
	go g.walkFromEdgeToRoot(start, out)
	return out
}

// WalkChains is the same as WalkChainsAsync, except synchronous.
func (g *Graph) WalkChains(c *x509.Certificate) (out []x509.CertificateChain) {
	chainChan := g.WalkChainsAsync(c, WalkOptions{})
	for chain := range chainChan {
		out = append(out, chain)
	}
	return
}

func (g *Graph) walkFromEdgeToRoot(start *GraphEdge, out chan x509.CertificateChain) {
	soFar := x509.CertificateChain{start.Certificate}
	g.continueWalking(out, start, start.issuer, soFar, start)
	close(out)
	return
}

func (g *Graph) continueWalking(found chan x509.CertificateChain, start *GraphEdge, current *GraphNode, soFar x509.CertificateChain, lastEdge *GraphEdge) {
	// If the chain ends at a root certificate, send the chain through the out
	// channel.
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
			certType := x509.CertificateTypeIntermediate
			if edge.root {
				certType = x509.CertificateTypeRoot
			}
			if canAddToChain(edge.Certificate, certType, soFar) != nil {
				continue
			}
			nextSoFar := soFar.AppendToFreshChain(edge.Certificate)
			g.continueWalking(found, start, edge.issuer, nextSoFar, edge)
		}

	}
	return
}

// isValid performs validity checks on the c. It will never return a
// date-related error.
func canAddToChain(c *x509.Certificate, certType x509.CertificateType, currentChain x509.CertificateChain) error {

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing.  Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.
	if certType == x509.CertificateTypeIntermediate && (!c.BasicConstraintsValid || !c.IsCA) {
		return x509.CertificateInvalidError{Cert: c, Reason: x509.NotAuthorizedToSign}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return x509.CertificateInvalidError{Cert: c, Reason: x509.TooManyIntermediates}
		}
	}

	return nil
}
