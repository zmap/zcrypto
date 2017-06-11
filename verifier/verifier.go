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
	"time"

	"github.com/zmap/zcrypto/x509"
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
	CurrentChains [][]*x509.Certificate

	// ExpiredChains is a list of certificate chains that were valid at some
	// point, but not at ValidationTime.
	ExpiredChains [][]*x509.Certificate

	// NeverValidChains is a list of certificate chains that could never be valid
	// due to date-related issues, but are otherwise valid.
	NeverValidChains [][]*x509.Certificate

	// ValidAtExpirationChains is a list of certificate chains that were valid at
	// the time of expiration of the certificate being validated.
	ValidAtExpirationChains [][]*x509.Certificate

	// CertificateType is one of Leaf, Intermediate, or Root.
	CertificateType x509.CertificateType

	// VerifyTime is time used in verification, set in the VerificationOptions.
	VerifyTime time.Time

	// Expired is false if NotBefore < VerifyTime < NotAfter
	Expired bool
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

// VerificationOptions contains settings for Verifier.Verify().
// VerificationOptions should be safely copyable.
type VerificationOptions struct {
	VerifyTime     time.Time
	Name           string
	PresentedChain *x509.CertPool
}

func (opt *VerificationOptions) clean() {
	if opt.VerifyTime.IsZero() {
		opt.VerifyTime = time.Now()
	}
}

// A Verifier represents a context for verifying certificates.
type Verifier struct {
	Roots           *x509.CertPool
	Intermediates   *x509.CertPool
	VerifyProcedure VerifyProcedure
}

func (v *Verifier) convertOptions(opt *VerificationOptions) (out x509.VerifyOptions) {
	out.CurrentTime = opt.VerifyTime
	out.Roots = v.Roots
	if opt.PresentedChain != nil && opt.PresentedChain.Size() > 0 {
		out.Intermediates = v.Intermediates.Sum(opt.PresentedChain)
	} else {
		out.Intermediates = v.Intermediates
	}
	out.DNSName = opt.Name
	out.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	return
}

func parentsFromChains(chains [][]*x509.Certificate) (parents []*x509.Certificate) {
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
	opts.clean()
	xopts := v.convertOptions(&opts)

	res = new(VerificationResult)
	res.Name = opts.Name
	res.Expired = !c.TimeInValidityPeriod(opts.VerifyTime)

	// Don't pass DNSName to x509.Verify(), we'll check it ourselves by calling
	// VerifyHostname() if necessary.
	xopts.DNSName = ""

	// Build chains back to the roots. If we have a DNSName, verify the leaf
	// certificate matches.
	res.CurrentChains, res.ExpiredChains, res.NeverValidChains, res.ValidationError = c.Verify(xopts)
	if len(opts.Name) > 0 {
		res.NameError = c.VerifyHostname(opts.Name)
	}

	var allChains [][]*x509.Certificate
	allChains = append(allChains, res.CurrentChains...)
	allChains = append(allChains, res.ExpiredChains...)
	allChains = append(allChains, res.NeverValidChains...)

	expirationTime := c.NotAfter.Add(-time.Second)
	res.ValidAtExpirationChains, _, _ = x509.FilterByDate(allChains, expirationTime)

	// Calculate the parents at the time of expiration.
	res.Parents = parentsFromChains(res.ValidAtExpirationChains)

	// Determine certificate type.
	if xopts.Roots.Contains(c) {
		// A certificate is only a root if it's in the root store.
		res.CertificateType = x509.CertificateTypeRoot
	} else if c.IsCA && len(res.ValidAtExpirationChains) > 0 {
		// We define an intermediate as any certificate that is not a root, but has
		// IsCA = true and at least one chain valid at the time it expires.
		res.CertificateType = x509.CertificateTypeIntermediate
	} else {
		// If a certificate is not a root or an intermediate, we'll call it a leaf.
		res.CertificateType = x509.CertificateTypeLeaf
	}

	return
}
