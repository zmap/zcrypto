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
	"context"
	"encoding/hex"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zcrypto/x509/revocation/crl"
	"github.com/zmap/zcrypto/x509/revocation/google"
	"github.com/zmap/zcrypto/x509/revocation/mozilla"
)

// VerificationResult contains the result of a verification of a certificate
// against a store and its associated policies. It discerns between NameError,
// meaning the name on the certificate does not match, and a ValidationError,
// meaning some sort of issue with the cryptography, or other issues with the
// chain.
type VerificationResult struct {

	// The name being checked, e.g. "www.censys.io".
	Name string

	// Whitelisted is true if the certificate is whitelisted by a given verifier
	// as trusted, e.g. when Apple whitelisted subset of StartCom certs by SPKI
	// hash in the wake of the WoSign incidents surrounding misissuance.
	Whitelisted bool

	// Blacklisted is true if the certificate is blacklisted by a given verifier
	// as untrusted, e.g. Cloudflare certificates valid at the time of Heartbleed
	// disclosure in Chrome.
	Blacklisted bool

	// InRevocationSet is true if the certificate has been revoked and is listed
	// in the revocation set that is part of the Verifier (e.g. in OneCRL).
	InRevocationSet bool

	// OCSPRevoked is true if the certificate has been revoked through OCSP,
	// which is only checked if VerificationOptions.ShouldCheckOCSP flag is set
	OCSPRevoked bool

	// OCSPRevocationInfo provides revocation info when OCSPRevoked is true
	OCSPRevocationInfo *RevocationInfo

	// CRLRevoked is true if the certificate has been revoked through CRL,
	// which is only checked if VerificationOptions.ShouldCheckCRL flag is set
	CRLRevoked bool

	// CRLRevocationInfo provides revocation info when CRLRevoked is true
	CRLRevocationInfo *RevocationInfo

	// OCSPCheckError will be non-nil when there was some sort of error from OCSP check
	OCSPCheckError error

	// CRLCheckError will be non-nil when there was some sort of error from CRL check
	CRLCheckError error

	// ValiditionError will be non-nil when there was some sort of error during
	// validation not involving a name mismatch, e.g. if a chain could not be
	// built.
	ValidationError error

	// NameError will be non-nil when there was a mismatch between the name on the
	// certificate and the name being verified against.
	NameError error

	// Parents is a set of currently valid certificates that are immediate parents
	// of the certificate being verified, and are part of a chain that is valid at
	// the time the certificate being verified expires.
	Parents []*x509.Certificate

	// CurrentChains is a list of validated certificate chains that are valid at
	// ValidationTime, starting at the certificate being verified, and ending at a
	// certificate in the root store.
	CurrentChains []x509.CertificateChain

	// ExpiredChains is a list of certificate chains that were valid at some
	// point, but not at ValidationTime.
	ExpiredChains []x509.CertificateChain

	// NeverValidChains is a list of certificate chains that could never be valid
	// due to date-related issues, but are otherwise valid.
	NeverValidChains []x509.CertificateChain

	// ValidAtExpirationChains is a list of certificate chains that were valid at
	// the time of expiration of the certificate being validated.
	ValidAtExpirationChains []x509.CertificateChain

	// CertificateType is one of Leaf, Intermediate, or Root.
	CertificateType x509.CertificateType

	// VerifyTime is time used in verification, set in the VerificationOptions.
	VerifyTime time.Time

	// Expired is false if NotBefore < VerifyTime < NotAfter
	Expired bool

	// ParentSPKISubjectFingerprint is the SHA256 of the (SPKI, Subject) for
	// parents of this certificate.
	ParentSPKISubjectFingerprint x509.CertificateFingerprint

	// ParentSPKI is the raw bytes of the subject public key info of the parent. It
	// is the SPKI used as part of the ParentSPKISubjectFingerprint.
	ParentSPKI []byte
}

// MatchesDomain returns true if NameError == nil and Name != "".
func (res *VerificationResult) MatchesDomain() bool {
	return res.NameError == nil && res.Name != ""
}

// HasTrustedChain returns true if len(current) > 0
func (res *VerificationResult) HasTrustedChain() bool {
	return len(res.CurrentChains) > 0
}

// HadTrustedChain returns true if at some point in time, the certificate had a
// chain to a trusted root in this store.
//
// This is equivalent to checking if len(Current) > 0 || len(ValidAtExpired) > 0
func (res *VerificationResult) HadTrustedChain() bool {
	return res.HasTrustedChain() || len(res.ValidAtExpirationChains) > 0
}

// VerifyProcedure is an interface to implement additional browser specific logic at
// the start and end of verification.
type VerifyProcedure interface {
	// TODO
}

// RevocationInfo provides basic revocation information
type RevocationInfo struct {
	NextUpdate     time.Time
	RevocationTime *time.Time
	Reason         crl.RevocationReasonCode
}

// RevocationProvider is an interface to implement revocation status provider
type RevocationProvider interface {
	// CheckOCSP - check the ocsp status of a provided certificate
	CheckOCSP(ctx context.Context, c *x509.Certificate, issuer *x509.Certificate) (isRevoked bool, info *RevocationInfo, e error)
	// CheckCRL - check whether the provided certificate has been revoked through
	// a CRL. If no certList is provided, function will attempt to fetch it.
	CheckCRL(ctx context.Context, c *x509.Certificate, certList *pkix.CertificateList) (isRevoked bool, info *RevocationInfo, err error)
}

// VerificationOptions contains settings for Verifier.Verify().
// VerificationOptions should be safely copyable.
type VerificationOptions struct {
	VerifyTime         time.Time
	Name               string
	PresentedChain     *Graph // XXX: Unused
	ShouldCheckOCSP    bool
	ShouldCheckCRL     bool
	RevocationProvider RevocationProvider
	CRLSet             *google.CRLSet
	OneCRL             *mozilla.OneCRL
}

func (opt *VerificationOptions) clean() {
	if opt.VerifyTime.IsZero() {
		opt.VerifyTime = time.Now()
	}
}

// A Verifier represents a context for verifying certificates.
type Verifier struct {
	PKI             *Graph
	VerifyProcedure VerifyProcedure
}

// NewVerifier returns and initializes a new Verifier given a PKI graph and set
// of verification procedures.
func NewVerifier(pki *Graph, verifyProc VerifyProcedure) *Verifier {
	out := new(Verifier)
	out.PKI = pki
	out.VerifyProcedure = verifyProc
	return out
}

func parentsFromChains(chains []x509.CertificateChain) (parents []*x509.Certificate) {
	// parentSet is a map from FingerprintSHA256 to the index of the chain the
	// parent was in. We use this to deduplicate parents.
	parentSet := make(map[string]int)
	for chainIdx, chain := range chains {
		if len(chain) < 2 {
			continue
		}
		parent := chain[1]
		// We can overwrite safely. If a parent is in multiple chains, we don't
		// actually care which chain we pull the parent from.
		parentSet[string(parent.FingerprintSHA256)] = chainIdx
	}
	// Convert the map to a slice.
	for _, chainIdx := range parentSet {
		// The parents are always at index 1 in the chain.
		parents = append(parents, chains[chainIdx][1])
	}
	return
}

// Verify checks if c chains back to a certificate in Roots, possibly via a
// certificate in Intermediates, and returns all such chains. It additional
// checks if the Name in the VerificationOptions matches the name on the
// certificate.
func (v *Verifier) Verify(c *x509.Certificate, opts VerificationOptions) (res *VerificationResult) {
	return v.VerifyWithContext(context.Background(), c, opts)
}

// VerifyWithContext checks if c chains back to a certificate in Roots, possibly via a
// certificate in Intermediates, and returns all such chains. It additional
// checks if the Name in the VerificationOptions matches the name on the
// certificate.
func (v *Verifier) VerifyWithContext(ctx context.Context, c *x509.Certificate, opts VerificationOptions) (res *VerificationResult) {
	opts.clean()

	res = new(VerificationResult)
	res.Name = opts.Name
	res.Expired = !c.TimeInValidityPeriod(opts.VerifyTime)

	// Build chains back to the roots.
	graphChains := v.PKI.WalkChains(c)
	res.CurrentChains, res.ExpiredChains, res.NeverValidChains = x509.FilterByDate(graphChains, opts.VerifyTime)

	// If we have a DNSName, verify the leaf certificate matches.
	if len(opts.Name) > 0 {
		res.NameError = c.VerifyHostname(opts.Name)
	}

	var allChains []x509.CertificateChain
	allChains = append(allChains, res.CurrentChains...)
	allChains = append(allChains, res.ExpiredChains...)
	allChains = append(allChains, res.NeverValidChains...)

	expirationTime := c.NotAfter.Add(-time.Second)
	res.ValidAtExpirationChains, _, _ = x509.FilterByDate(allChains, expirationTime)

	// Calculate the parents at the time of expiration for expired certs.
	if res.Expired {
		res.Parents = parentsFromChains(res.ValidAtExpirationChains)
	} else {
		res.Parents = parentsFromChains(res.CurrentChains)
	}

	if opts.OneCRL != nil && opts.OneCRL.Check(c) != nil {
		res.InRevocationSet = true
	}
	if !res.InRevocationSet && opts.CRLSet != nil {
		for _, parent := range res.Parents {
			if opts.CRLSet.Check(c, hex.EncodeToString(parent.SPKIFingerprint)) != nil {
				res.InRevocationSet = true
				break
			}
		}
	}

	rp := opts.RevocationProvider
	if rp == nil {
		rp = defaultRevocation{}
	}

	if opts.ShouldCheckOCSP && len(c.OCSPServer) > 0 {
		var issuer *x509.Certificate
		if res.Parents != nil {
			issuer = res.Parents[0] // only need issuer SPKI, so any parent will do
		} else {
			issuer = nil
		}
		res.OCSPRevoked, res.OCSPRevocationInfo, res.OCSPCheckError = rp.CheckOCSP(ctx, c, issuer)
	}

	if opts.ShouldCheckCRL && len(c.CRLDistributionPoints) > 0 {
		res.CRLRevoked, res.CRLRevocationInfo, res.CRLCheckError = rp.CheckCRL(ctx, c, nil)
	}

	// Determine certificate type.
	if v.PKI.IsRoot(c) {
		// A certificate is only a root if it's in the root store.
		res.CertificateType = x509.CertificateTypeRoot
	} else if c.IsCA && len(res.Parents) > 0 {
		// We define an intermediate as any certificate that is not a root, but has
		// IsCA = true and at least one parent.
		res.CertificateType = x509.CertificateTypeIntermediate
	} else if len(res.Parents) > 0 {
		// If a certificate is not a root or an intermediate, but has a parent,
		// we'll call it a leaf.
		res.CertificateType = x509.CertificateTypeLeaf
	} else {
		// Default to Unknown
		res.CertificateType = x509.CertificateTypeUnknown
	}

	// Set the ParentSPKISubjectFingerprint and ParentSPKI
	if len(res.Parents) > 0 {
		// All parents should have the same (SPKI, Subject) fingerprint. If not,
		// there's a bug.
		fp := res.Parents[0].SPKISubjectFingerprint
		res.ParentSPKISubjectFingerprint = make([]byte, len(fp))
		copy(res.ParentSPKISubjectFingerprint, fp)
		parentSPKI := res.Parents[0].RawSubjectPublicKeyInfo
		res.ParentSPKI = make([]byte, len(parentSPKI))
		copy(res.ParentSPKI, parentSPKI)
	}

	return
}

type defaultRevocation struct{}

// CheckOCSP - check the ocsp status of a provided certificate
func (defaultRevocation) CheckOCSP(ctx context.Context, c *x509.Certificate, issuer *x509.Certificate) (isRevoked bool, info *RevocationInfo, e error) {
	return CheckOCSP(ctx, c, issuer)
}

// CheckCRL - check whether the provided certificate has been revoked through
// a CRL. If no certList is provided, function will attempt to fetch it.
func (defaultRevocation) CheckCRL(ctx context.Context, c *x509.Certificate, certList *pkix.CertificateList) (isRevoked bool, info *RevocationInfo, err error) {
	return CheckCRL(ctx, c, certList)
}
