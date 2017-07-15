// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import "fmt"

func (sk *SubjectAndKey) subjectAndKeyFingerprint() subjectAndKeyFingerprint {
	return subjectAndKeyFingerprint(sk.Fingerprint)
}

// subjectAndKeyFingerprint is a SHA256 fingerprint of (public key, subject).
// This is used a key in maps.
type subjectAndKeyFingerprint string

// CertificateChain is a slice of certificates. The 0'th element is the leaf,
// and the last element is a root. Successive elements have a child-parent
// relationship.
type CertificateChain []*Certificate

// Graph represents signing relationships between SubjectAndKey tuples. A node
// in the graph is a SubjectAndKey. An edge in the graph is a certificate issued
// by the direct predecessor (tail) to the direct successor (head).
type Graph struct {
	nodes                []*GraphNode
	edges                *GraphEdgeSet
	nodesBySubjectAndKey map[subjectAndKeyFingerprint]*GraphNode
	nodesBySubject       map[string][]*GraphNode  // indexed by RawSubject
	missingIssuerNode    map[string]*GraphEdgeSet // indexed by RawIssuer
}

// A GraphNode is a SubjectAndKey
type GraphNode struct {
	SubjectAndKey           *SubjectAndKey
	childrenBySubjectAndKey map[subjectAndKeyFingerprint]*GraphEdgeSet
}

// A GraphEdge is a certificate that joins two SubjectAndKeys.
type GraphEdge struct {
	Certificate *Certificate
	issuer      *GraphNode // this might not always be filled out
	child       *GraphNode
}

// A GraphEdgeSet represents a set of edges. Edges are deduplicated by
// certificate fingerprint.
type GraphEdgeSet struct {
	edges map[string]*GraphEdge
}

// NewGraph initializes an empty Graph.
func NewGraph() (g *Graph) {
	g = new(Graph)
	g.edges = NewGraphEdgeSet()
	g.nodesBySubjectAndKey = make(map[subjectAndKeyFingerprint]*GraphNode)
	g.nodesBySubject = make(map[string][]*GraphNode)
	g.missingIssuerNode = make(map[string]*GraphEdgeSet)
	return
}

// Nodes returns a slice of all nodes in the graph.
func (g *Graph) Nodes() (out []*GraphNode) {
	if g.nodes == nil {
		return
	}
	out = make([]*GraphNode, len(g.nodes))
	copy(out, g.nodes)
	return
}

// Edges returns all edges in the graph as a slice.
func (g *Graph) Edges() []*GraphEdge {
	return g.edges.Edges()
}

// FindEdge returns an edge with a certificate matching the given SHA256
// fingerprint, if it exists. If it does not exist, FindEdge returns nil.
func (g *Graph) FindEdge(fp CertificateFingerprint) *GraphEdge {
	return g.edges.FindEdge(fp)
}

// FindNode returns a node with a matching spki_subject_fingerprint to fp, if it
// exists. If it does not exist, FindNode returns nil.
func (g *Graph) FindNode(fp CertificateFingerprint) *GraphNode {
	node := g.nodesBySubjectAndKey[subjectAndKeyFingerprint(fp)]
	return node
}

// AddCert inserts an edge for c into the graph, and creates nodes as needed.
func (g *Graph) AddCert(c *Certificate) {
	sk := c.SubjectAndKey()
	skfp := sk.subjectAndKeyFingerprint()
	isNewNode := false

	if g.edges.ContainsCertificate(c) {
		// This certificate is already represented in the graph.
		return
	}

	// Create a new edge for this certificate.
	edge := new(GraphEdge)
	edge.Certificate = c
	g.edges.addOrPanic(edge)

	// Make the node based on this certificates subject (or find it). Connect the
	// node to the edge as the successor / head.
	node := g.nodesBySubjectAndKey[skfp]
	if node == nil {
		node = new(GraphNode)
		node.SubjectAndKey = sk
		node.childrenBySubjectAndKey = make(map[subjectAndKeyFingerprint]*GraphEdgeSet)
		g.nodes = append(g.nodes, node)
		g.nodesBySubjectAndKey[skfp] = node

		s := string(c.RawSubject)
		g.nodesBySubject[s] = append(g.nodesBySubject[s], node)
		isNewNode = true
	}
	edge.child = node

	// Connect the edge to the graph
	//fmt.Fprintf(os.Stderr, "by subject %v\n", g.nodesBySubject)
	potentialIssuers, _ := g.nodesBySubject[string(c.RawIssuer)]
	for _, potentialIssuerNode := range potentialIssuers {
		issuerIdentity := potentialIssuerNode.SubjectAndKey
		if err := checkSignatureFromKey(issuerIdentity.PublicKey, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			// If the signature was not valid, this is not an issuer.
			continue
		}
		// The signature from the potential issuer was valid, and the subjects
		// match. Therefore, we have found an issuer. We now need to add the edge to
		// the graph. However, the graph is actually a multigraph. Two
		// SubjectAndKeys can be joined in the same direction multiple times, by
		// issuing multiple certificates to the same subject. Find all edges
		// corresponding to this issuer signing a certificate with the target
		// subject.
		edgeSet := potentialIssuerNode.childrenBySubjectAndKey[skfp]
		if edgeSet == nil {
			edgeSet = NewGraphEdgeSet()
			potentialIssuerNode.childrenBySubjectAndKey[skfp] = edgeSet
		}

		// Add this edge in. It should not already exist due to earlier checks. If
		// it prexists, the graph is corrupted.
		edge.issuer = potentialIssuerNode
		edgeSet.addOrPanic(edge)

		// A certificate can only be one edge. We found it already, so break out of
		// the loop.
		break
	}

	// Check if we have a reverse-dangling edge. This might be "patchable" as we
	// add more certificates.
	if edge.issuer == nil {
		rawIssuer := string(c.RawIssuer)
		missingIssuerSet := g.missingIssuerNode[rawIssuer]
		if missingIssuerSet == nil {
			missingIssuerSet = NewGraphEdgeSet()
			g.missingIssuerNode[rawIssuer] = missingIssuerSet
		}
		missingIssuerSet.addOrPanic(edge)
	}

	// Don't double add an edge.
	if c.SelfSigned {
		return
	}

	// If we added a new node, check if it issued an existing dangling edge.
	if !isNewNode {
		return
	}
	potentialOutgoingEdges := g.missingIssuerNode[string(c.RawSubject)]
	if potentialOutgoingEdges == nil {
		return
	}

	// Check every edge in the set to see if this node is an issuer.
	var fixedUpEdges []*GraphEdge
	for _, candidateEdge := range potentialOutgoingEdges.Edges() {
		pk := node.SubjectAndKey.PublicKey
		candidateCert := candidateEdge.Certificate
		if err := checkSignatureFromKey(pk, candidateCert.SignatureAlgorithm, candidateCert.RawTBSCertificate, candidateCert.Signature); err != nil {
			// If the signature was not valid, this node is not an issuer
			continue
		}

		// The signature was valid, so fixup this edge.
		candidateEdge.issuer = node
		childSubjectAndKeyFingerprint := candidateEdge.child.SubjectAndKey.subjectAndKeyFingerprint()
		edgeSet := node.childrenBySubjectAndKey[childSubjectAndKeyFingerprint]
		if edgeSet == nil {
			edgeSet = NewGraphEdgeSet()
			node.childrenBySubjectAndKey[childSubjectAndKeyFingerprint] = edgeSet
		}
		edgeSet.addOrPanic(candidateEdge)

		// Record the edge as fixed so we can remove it from the missingIssuerNode
		// map.
		fixedUpEdges = append(fixedUpEdges, candidateEdge)
	}

	// Remove any fixed-up edges from the missingIssuerNode map.
	for _, fixedEdge := range fixedUpEdges {
		potentialOutgoingEdges.RemoveEdge(fixedEdge.Certificate.FingerprintSHA256)
	}
	if potentialOutgoingEdges.Size() == 0 {
		potentialOutgoingEdges = nil
		delete(g.missingIssuerNode, string(c.RawSubject))
	}

}

// NewGraphEdgeSet initializes an empty GraphEdgeSet.
func NewGraphEdgeSet() (es *GraphEdgeSet) {
	es = new(GraphEdgeSet)
	es.edges = make(map[string]*GraphEdge)
	return
}

// Edges returns all edges in the set as a slice.
func (es *GraphEdgeSet) Edges() (out []*GraphEdge) {
	for _, edge := range es.edges {
		out = append(out, edge)
	}
	return
}

// ContainsCertificate returns true if c is contained in the GraphEdgeSet.
func (es *GraphEdgeSet) ContainsCertificate(c *Certificate) bool {
	fp := string(c.FingerprintSHA256)
	_, ok := es.edges[fp]
	return ok
}

// ContainsEdge returns true if the edge is contained in the GraphEdgeSet.
func (es *GraphEdgeSet) ContainsEdge(edge *GraphEdge) bool {
	return es.ContainsCertificate(edge.Certificate)
}

// Size returns the number of edges in the GraphEdgeSet.
func (es *GraphEdgeSet) Size() int {
	return len(es.edges)
}

// FindEdge returns an edge matching the certificate fingerprint, if it exists.
// If it does not exist, FindEdge returns nil.
func (es *GraphEdgeSet) FindEdge(fp CertificateFingerprint) *GraphEdge {
	edge, _ := es.edges[string(fp)]
	return edge
}

// RemoveEdge removes an edge matching the certificate fingerprint, if it
// exists. If it exists, RemoveEdge returns a point to the removed edge. If no
// such edge exists, RemoveEdge does nothing and returns nil.
func (es *GraphEdgeSet) RemoveEdge(fp CertificateFingerprint) *GraphEdge {
	edge, ok := es.edges[string(fp)]
	if !ok {
		return nil
	}
	delete(es.edges, string(fp))
	return edge
}

// addOrPanic adds the edge to the set, and panics if there is a fingerprint
// collision.
func (es *GraphEdgeSet) addOrPanic(edge *GraphEdge) {
	fp := string(edge.Certificate.FingerprintSHA256)
	if _, ok := es.edges[fp]; ok {
		panicStr := fmt.Sprintf("adding duplicate edge to set: %s", edge.Certificate.FingerprintSHA256.Hex())
		panic(panicStr)
	}
	es.edges[fp] = edge
}
