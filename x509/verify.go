// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// VerifyOptions contains parameters for Certificate.Verify. It's a structure
// because other PKIX verification APIs have ended up needing many options.
type VerifyOptions struct {
	DNSName      string
	EmailAddress string
	IPAddress    net.IP

	Intermediates *CertPool
	Roots         *CertPool // if nil, the system roots are used
	CurrentTime   time.Time // if zero, the current time is used
	// KeyUsage specifies which Extended Key Usage values are acceptable.
	// An empty list means ExtKeyUsageServerAuth. Key usage is considered a
	// constraint down the chain which mirrors Windows CryptoAPI behaviour,
	// but not the spec. To accept any key usage, include ExtKeyUsageAny.
	KeyUsages []ExtKeyUsage
}

// isValid performs validity checks on the c. It will never return a
// date-related error.
func (c *Certificate) isValid(certType CertificateType, currentChain []*Certificate, opts *VerifyOptions) error {
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	// The name constraints extension, which MUST be used only in a CA
	// certificate, indicates a name space within which all subject names in
	// subsequent certificates in a certification path MUST be located.
	if certType != CertificateTypeLeaf {
		// PermittedDNSDomains
		if len(opts.DNSName) > 0 && len(c.PermittedDNSDomains) > 0 {
			ok := false
			for _, domain := range c.PermittedDNSDomains {
				if opts.DNSName == domain.Data ||
					(strings.HasPrefix(domain.Data, ".") && strings.HasSuffix(opts.DNSName, domain.Data)) ||
					(!strings.HasPrefix(domain.Data, ".") && strings.HasSuffix(opts.DNSName, "."+domain.Data)) {

					ok = true
					break
				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisName}
			}
		}

		// ExcludedDNSDomains
		if len(opts.DNSName) > 0 && len(c.ExcludedDNSDomains) > 0 {
			ok := false
			for _, domain := range c.ExcludedDNSDomains {
				if opts.DNSName == domain.Data ||
					(strings.HasPrefix(domain.Data, ".") && strings.HasSuffix(opts.DNSName, domain.Data)) ||
					(!strings.HasPrefix(domain.Data, ".") && strings.HasSuffix(opts.DNSName, "."+domain.Data)) {

					ok = true
					break
				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisName}
			}
		}

		// PermittedEmailDomains
		if len(opts.EmailAddress) > 0 && len(c.PermittedEmailDomains) > 0 {
			ok := false
			for _, email := range c.PermittedEmailDomains {
				if opts.EmailAddress == email.Data ||
					(strings.HasPrefix(email.Data, ".") && strings.HasSuffix(opts.EmailAddress, email.Data)) ||
					(!strings.HasPrefix(email.Data, ".") && strings.HasSuffix(opts.EmailAddress, "@"+email.Data)) {

					ok = true
					break

				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisEmail}
			}
		}

		// ExcludedEmailDomains
		if len(opts.EmailAddress) > 0 && len(c.ExcludedEmailDomains) > 0 {
			ok := true
			for _, email := range c.PermittedEmailDomains {
				if opts.EmailAddress == email.Data ||
					(strings.HasPrefix(email.Data, ".") && strings.HasSuffix(opts.EmailAddress, email.Data)) ||
					(!strings.HasPrefix(email.Data, ".") && strings.HasSuffix(opts.EmailAddress, "@"+email.Data)) {

					ok = false
					break
				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisEmail}
			}
		}

		// PermittedIPAddresses
		if len(opts.IPAddress) > 0 && len(c.PermittedIPAddresses) > 0 {
			ok := false
			for _, ip := range c.PermittedIPAddresses {
				if ip.Data.Contains(opts.IPAddress) {
					ok = true
					break
				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisIP}
			}
		}

		// ExcludedIPAddresses
		if len(opts.IPAddress) > 0 && len(c.ExcludedIPAddresses) > 0 {
			ok := true
			for _, ip := range c.ExcludedIPAddresses {
				if ip.Data.Contains(opts.IPAddress) {
					ok = false
					break
				}
			}

			if !ok {
				return CertificateInvalidError{c, CANotAuthorizedForThisIP}
			}
		}

		// Directory Names need to be checked against the leaf certificate
		if len(currentChain) > 0 {
			leaf := currentChain[0]

			// PermittedDirectoryNames
			if len(leaf.Subject.Names) > 0 && len(c.PermittedDirectoryNames) > 0 {
				for _, name := range leaf.Subject.Names {
					for _, dn := range c.PermittedDirectoryNames {
						ok := true
						for _, dnName := range dn.Data.Names {
							if name.Type.Equal(dnName.Type) {
								ok = false
								if fmt.Sprintf("%v", name.Value) == fmt.Sprintf("%v", dnName.Value) {
									ok = true
									break
								}
							}
						}

						if !ok {
							return CertificateInvalidError{c, CANotAuthorizedForThisDirectory}
						}

					}
				}
			}

			// ExcludedDirectoryNames
			if len(leaf.Subject.Names) > 0 && len(c.ExcludedDirectoryNames) > 0 {
				for _, name := range leaf.Subject.Names {
					for _, dn := range c.ExcludedDirectoryNames {
						ok := true
						for _, dnName := range dn.Data.Names {
							if name.Type.Equal(dnName.Type) {
								ok = true
								if fmt.Sprintf("%v", name.Value) == fmt.Sprintf("%v", dnName.Value) {
									ok = false
									break
								}
							}
						}

						if !ok {
							return CertificateInvalidError{c, CANotAuthorizedForThisDirectory}
						}

					}
				}
			}
		}
	}

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

	if certType == CertificateTypeIntermediate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates}
		}
	}

	return nil
}

// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// If opts.Roots is nil and system roots are unavailable the returned error
// will be of type SystemRootsError.
//
// WARNING: this doesn't do any revocation checking.
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {

	// TODO: Populate with the correct OID
	if len(c.UnhandledCriticalExtensions) > 0 {
		return nil, UnhandledCriticalExtension{nil, ""}
	}

	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			return nil, SystemRootsError{}
		}
	}

	err = c.isValid(CertificateTypeLeaf, nil, &opts)
	if err != nil {
		return
	}

	candidateChains, err := c.buildChains(make(map[int][][]*Certificate), []*Certificate{c}, &opts)
	if err != nil {
		return
	}

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}

	// If any key usage is acceptable then we're done.
	hasKeyUsageAny := false
	for _, usage := range keyUsages {
		if usage == ExtKeyUsageAny {
			hasKeyUsageAny = true
			break
		}
	}

	if hasKeyUsageAny {
		chains = candidateChains
	} else {
		for _, candidate := range candidateChains {
			if checkChainForKeyUsage(candidate, keyUsages) {
				chains = append(chains, candidate)
			}
		}
	}

	if len(chains) == 0 {
		err = CertificateInvalidError{c, IncompatibleUsage}
	}

	chains, expired, never := checkExpirations(chains, opts.CurrentTime)
	if len(chains) == 0 {
		if len(expired) > 0 {
			err = CertificateInvalidError{c, Expired}
		} else if len(never) > 0 {
			err = CertificateInvalidError{c, NeverValid}
		}
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}
	return
}

func appendToFreshChain(chain []*Certificate, cert *Certificate) []*Certificate {
	n := make([]*Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}

func (c *Certificate) buildChains(cache map[int][][]*Certificate, currentChain []*Certificate, opts *VerifyOptions) (chains [][]*Certificate, err error) {
	possibleRoots, failedRoot, rootErr := opts.Roots.findVerifiedParents(c)
	for _, rootNum := range possibleRoots {
		root := opts.Roots.certs[rootNum]
		err = root.isValid(CertificateTypeRoot, currentChain, opts)
		if err != nil {
			continue
		}
		chains = append(chains, appendToFreshChain(currentChain, root))
	}

	possibleIntermediates, failedIntermediate, intermediateErr := opts.Intermediates.findVerifiedParents(c)
nextIntermediate:
	for _, intermediateNum := range possibleIntermediates {
		intermediate := opts.Intermediates.certs[intermediateNum]
		for _, cert := range currentChain {
			if cert.Equal(intermediate) {
				continue nextIntermediate
			}
		}
		err = intermediate.isValid(CertificateTypeIntermediate, currentChain, opts)
		if err != nil {
			continue
		}
		var childChains [][]*Certificate
		childChains, ok := cache[intermediateNum]
		if !ok {
			childChains, err = intermediate.buildChains(cache, appendToFreshChain(currentChain, intermediate), opts)
			cache[intermediateNum] = childChains
		}
		chains = append(chains, childChains...)
	}

	if len(chains) > 0 {
		err = nil
	}

	if len(chains) == 0 && err == nil {
		hintErr := rootErr
		hintCert := failedRoot
		if hintErr == nil {
			hintErr = intermediateErr
			hintCert = failedIntermediate
		}
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

func matchHostnames(pattern, host string) bool {
	host = strings.TrimSuffix(host, ".")
	pattern = strings.TrimSuffix(pattern, ".")

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if /*i == 0 &&*/ patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

// earlier returns the earlier of a and b
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// later returns the later of a and b
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// check expirations divides chains into a set of disjoint chains, containing
// current chains valid now, expired chains that were valid at some point, and
// the set of chains that were never valid.
func checkExpirations(chains [][]*Certificate, now time.Time) (current, expired, never [][]*Certificate) {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		leaf := chain[0]
		lowerBound := leaf.NotBefore
		upperBound := leaf.NotAfter
		for _, c := range chain[1:] {
			lowerBound = later(lowerBound, c.NotBefore)
			upperBound = earlier(upperBound, c.NotAfter)
		}
		valid := lowerBound.Before(now) && upperBound.After(now)
		wasValid := lowerBound.Before(upperBound)
		if valid && !wasValid {
			// Math/logic tells us this is impossible.
			panic("valid && !wasValid should not be possible")
		}
		if valid {
			current = append(current, chain)
		} else if wasValid {
			expired = append(expired, chain)
		} else {
			never = append(never, chain)
		}
	}
	return
}

// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// VerifyHostname returns nil if c is a valid certificate for the named host.
// Otherwise it returns an error describing the mismatch.
func (c *Certificate) VerifyHostname(h string) error {
	// IP addresses may be written in [ ].
	candidateIP := h
	if len(h) >= 3 && h[0] == '[' && h[len(h)-1] == ']' {
		candidateIP = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(candidateIP); ip != nil {
		// We only match IP addresses against IP SANs.
		// https://tools.ietf.org/html/rfc6125#appendix-B.2
		for _, candidate := range c.IPAddresses {
			if ip.Equal(candidate) {
				return nil
			}
		}
		return HostnameError{c, candidateIP}
	}

	lowered := toLowerCaseASCII(h)

	if len(c.DNSNames) > 0 {
		for _, match := range c.DNSNames {
			if matchHostnames(toLowerCaseASCII(match), lowered) {
				return nil
			}
		}
		// If Subject Alt Name is given, we ignore the common name.
	} else if matchHostnames(toLowerCaseASCII(c.Subject.CommonName), lowered) {
		return nil
	}

	return HostnameError{c, h}
}

func checkChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool {
	usages := make([]ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)

	// We walk down the list and cross out any usages that aren't supported
	// by each certificate. If we cross out all the usages, then the chain
	// is unacceptable.

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			// The certificate doesn't have any extended key usage specified.
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == ExtKeyUsageAny {
				// The certificate is explicitly good for any usage.
				continue NextCert
			}
		}

		const invalidUsage ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				} else if requestedUsage == ExtKeyUsageServerAuth &&
					(usage == ExtKeyUsageNetscapeServerGatedCrypto ||
						usage == ExtKeyUsageMicrosoftServerGatedCrypto) {
					// In order to support COMODO
					// certificate chains, we have to
					// accept Netscape or Microsoft SGC
					// usages as equal to ServerAuth.
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}
