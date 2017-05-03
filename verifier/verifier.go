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

	// Revoked is true if the certificate has been revoked and is listed in the
	// revocation set that is part of the Verifier (e.g. in OneCRL).
	Revoked bool

	// ValiditionError will be non-nil when there was some sort of error during
	// validation not involving a name mismatch, e.g. if a chain could not be
	// built.
	ValidationError error

	// NameError will be non-nil when there was a mismatch between the name on the
	// certificate and the name being verified against.
	NameError error

	// Current is a list of validated certificate chains that are valid at
	// ValidationTime, starting at the certificate being verified, and ending at a
	// certificate in the root store.
	Current [][]*x509.Certificate

	// Expired is a list of certificate chains that were valid at some point,
	// but not at ValidationTime.
	Expired [][]*x509.Certificate

	// Never is a list of certificate chains that could never be valid due to
	// date-related issues, but are otherwise valid.
	Never [][]*x509.Certificate
}

// MatchesDomain returns true if NameError == nil and Name != "".
func (res *VerificationResult) MatchesDomain() bool {
	return res.NameError == nil && res.Name != ""
}

// VerifyProcedure is an interface to implement additional browser specific logic at
// the start and end of verification.
type VerifyProcedure interface {
	// TODO
}

// VerificationOptions contains settings for Verifier.Verify().
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

// A Verifier represents a context for verifying certificates.
type Verifier struct {
	Roots           *x509.CertPool
	Intermediates   *x509.CertPool
	VerifyProcedure VerifyProcedure
}

func (v *Verifier) convertOptions(opt *VerificationOptions) (out x509.VerifyOptions) {
	opt.clean()
	out.CurrentTime = opt.VerifyTime
	out.Roots = v.Roots
	out.Intermediates = v.Intermediates
	out.DNSName = opt.Name
	out.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	return
}

// Verify checks if c chains back to a certificate in Roots, possibly via a
// certificate in Intermediates, and returns all such chains. It additional
// checks if the Name in the VerificationOptions matches the name on the
// certificate.
func (v *Verifier) Verify(c *x509.Certificate, opts VerificationOptions) (res *VerificationResult) {
	res = new(VerificationResult)
	res.Name = opts.Name

	if res.ValidationError == nil {
		xopts := v.convertOptions(&opts)

		// Don't pass DNSName to x509.Verify(), we'll check it ourselves by calling
		// VerifyHostname() if necessary.
		xopts.DNSName = ""

		res.Current, res.Expired, res.Never, res.ValidationError = c.Verify(xopts)
		if len(opts.Name) > 0 {
			res.NameError = c.VerifyHostname(opts.Name)
		}
	}

	return
}
