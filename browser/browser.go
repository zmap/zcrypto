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

package browser

import (
	"time"

	"github.com/zmap/zcrypto/x509"
)

// VerificationResult contains the result of a verification of a certificate
// against a Browser. It discerns between NameError, meaning the name on the
// certificate does not match, and a ValidationError, meaning some sort of issue
// with the cryptography, or other issues with the chain.
type VerificationResult struct {

	// The name being checked, e.g. "www.censys.io".
	Name string

	// True if the certificate is whitelisted by a given browser as trusted, e.g.
	// when Apple whitelisted subset of StartCom certs by SPKI hash in the wake of
	// the WoSign incidents surrounding misissuance.
	Whitelisted bool

	// True is the certificate is blacklisted by a given browser as untrusted,
	// e.g. Cloudflare certificates valid at the time of Heartbleed disclosure in
	// Chrome.
	Blacklisted bool

	// ValiditionError will be non-nil when there was some sort of error during
	// validation not involving a name mismatch, e.g. if a chain could not be
	// built.
	ValidationError error

	// NameError will be non-nil when there was a mismatch between the name on the
	// certificate and the name being verified against.
	NameError error

	// Chains is a list of validated certificate chains, starting at the
	// certificate being verified, and ending at a certificate in the root store.
	Chains [][]*x509.Certificate
}

// MatchesDomain returns true if NameError == nil and Name != "".
func (res *VerificationResult) MatchesDomain() bool {
	return res.NameError == nil && res.Name != ""
}

// Verifier is an interface to implement additional browser specific logic at
// the start and end of verification.
type Verifier interface {
	PreValidate(c *x509.Certificate) error
	PostValidate(c *x509.Certificate, chains [][]*x509.Certificate) error
}

// VerificationOptions contains settings for Browser.Verify().
// VerificationOptions should be safely copyable.
type VerificationOptions struct {
	VerifyTime time.Time
	Name       string
}

func (opt *VerificationOptions) clean() {
	if opt.VerifyTime.IsZero() {
		opt.VerifyTime = time.Now()
	}
}

// A Browser represents a context for verifying certificates.
type Browser struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	Blacklist     *x509.CertPool
	Whitelist     *x509.CertPool
	Verifier      Verifier
}

func (b *Browser) convertOptions(opt *VerificationOptions) (out x509.VerifyOptions) {
	opt.clean()
	out.CurrentTime = opt.VerifyTime
	out.Roots = b.Roots
	out.Intermediates = b.Intermediates
	out.DNSName = opt.Name
	return
}

// Verify checks if c chains back to a certificate in Roots, possibly via a
// certificate in Intermediates, and returns all such chains. It additional
// checks if the Name in the VerificationOptions matches the name on the
// certificate. Finally, it checks to see if c is blacklisted or whitelisted by
// the Browser.
func (b *Browser) Verify(c *x509.Certificate, opts VerificationOptions) (res *VerificationResult) {
	res = new(VerificationResult)
	res.Name = opts.Name

	// Always run prevalidate.
	if err := b.Verifier.PreValidate(c); err != nil {
		res.ValidationError = err
	}

	// XXX: x509 should expose the validation we want with out this struct
	// designed for JSON output.
	if res.ValidationError == nil {
		xopts := b.convertOptions(&opts)
		chains, validation, _ := c.ValidateWithStupidDetail(xopts)
		res.Chains = chains
		res.ValidationError = validation.ValidationError
		res.NameError = validation.NameError
		res.Chains = chains
	}

	// Run PostValidate if there was no exisiting validation error.
	if res.ValidationError == nil {
		if err := b.Verifier.PostValidate(c, res.Chains); err != nil {
			res.ValidationError = err
		}
	}

	// Check the whitelist
	if b.Whitelist.Contains(c) {
		res.Whitelisted = true
	}

	// Check the blacklist
	if b.Blacklist.Contains(c) {
		res.Blacklisted = true
	}

	return
}
