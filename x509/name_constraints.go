// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"net"
	"strings"

	"github.com/zmap/zcrypto/x509/pkix"
)

// GeneralName ::= CHOICE {
//      otherName                 [0]  AnotherName,
//      rfc822Name                [1]  IA5String,
//      dNSName                   [2]  IA5String,
//      x400Address               [3]  ORAddress,
//      directoryName             [4]  Name,
//      ediPartyName              [5]  EDIPartyName,
//      uniformResourceIdentifier [6]  IA5String,
//      iPAddress                 [7]  OCTET STRING,
//      registeredID              [8]  OBJECT IDENTIFIER }

// matchNameConstraints checks that the Certificate c falls within the name
// constraints defined in candidateChain.
func matchNameConstraints(certType CertificateType, c *Certificate, candidateChain [][]*Certificate) error {
	switch certType {
	case CertificateTypeLeaf:
	case CertificateTypeIntermediate:
	case CertificateTypeRoot:
	default:
		return nil
	}
	return nil
}

// matchDNSNames returns true if all names in child are covered by parent. If
// len(parent) == 0, then matchDNSNames returns empty.
func matchDNSNames(child []string, parent []GeneralSubtreeString, empty bool) bool {
	// XXX: Should this be defined on GeneralSubtreeString instead?
	if len(parent) == 0 {
		return empty
	}
	for _, name := range child {
		ok := false
		for _, constraint := range parent {
			if name == constraint.Data ||
				(strings.HasPrefix(constraint.Data, ".") && strings.HasSuffix(name, constraint.Data)) ||
				(!strings.HasPrefix(constraint.Data, ".") && strings.HasSuffix(name, "."+constraint.Data)) {

				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchEmailAddresses returns true if all email addresses in child are covered
// by parent. If len(parent) == 0, matchEmailAddresses returns empty.
func matchEmailAddresses(child []string, parent []GeneralSubtreeString, empty bool) bool {
	if len(parent) == 0 {
		return empty
	}
	for _, name := range child {
		ok := false
		for _, constraint := range parent {
			if (name == constraint.Data ||
				strings.HasPrefix(constraint.Data, ".") && strings.HasSuffix(name, constraint.Data)) ||
				(!strings.HasPrefix(constraint.Data, ".") && strings.HasSuffix(name, "@"+constraint.Data)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchIPAddresses returns true if all IP's in child are covered by parent. If
// len(parent) == 0, matchIPAddresses returns empty.
func matchIPAddresses(child []net.IP, parent []GeneralSubtreeIP, empty bool) bool {
	if len(parent) == 0 {
		return empty
	}
	for _, ip := range child {
		ok := false
		for _, constraint := range parent {
			if constraint.Data.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchX400Addresses return true is all X400 addresses in child are covered by
// parent, and returns empty if len(parent) == 0. Currently unimplemented, and
// always returns empty.
func matchX400Addresses(child []string, parent []GeneralSubtreeRaw, empty bool) bool {
	// TODO: Implement
	return empty
}

// matchDirectoryNames returns true if the DN of child is in parent. If
// len(parent) == 0, matchDirectoryNames returns empty.
func matchDirectoryNames(child *pkix.Name, parent []GeneralSubtreeName, empty bool) bool {
	return empty
}

func matchEDIPartyNames(child *pkix.EDIPartyName, parent []*pkix.EDIPartyName, empty bool) bool {
	// TODO: Implement
	return empty
}

func withinSubtrees(child *Certificate, parent *Certificate) error {
	// PermittedDNSDomains
	if permitted := matchDNSNames(child.DNSNames, parent.PermittedDNSNames, true); !permitted {
		return CertificateInvalidError{child, CANotAuthorizedForThisName}
	}
	// ExcludedDNSNames
	if excluded := matchDNSNames(child.DNSNames, parent.ExcludedDNSNames, false); excluded {
		return CertificateInvalidError{child, CANotAuthorizedForThisName}
	}
	// PermittedEmailDomains
	if permitted := matchEmailAddresses(child.EmailAddresses, parent.PermittedEmailAddresses, true); !permitted {
		return CertificateInvalidError{child, CANotAuthorizedForThisEmail}
	}
	// ExcludedEmailDomains
	if excluded := matchEmailAddresses(child.EmailAddresses, parent.PermittedEmailAddresses, false); excluded {
		return CertificateInvalidError{child, CANotAuthorizedForThisEmail}
	}
	// PermittedIPAddresses
	if permitted := matchIPAddresses(child.IPAddresses, parent.PermittedIPAddresses, true); !permitted {
		return CertificateInvalidError{child, CANotAuthorizedForThisIP}
	}
	// ExcludedIPAddresses
	if excluded := matchIPAddresses(child.IPAddresses, parent.ExcludedIPAddresses, false); excluded {
		return CertificateInvalidError{child, CANotAuthorizedForThisIP}
	}

	// TODO: Remaining constraint types
	// PermittedX400Addresses
	// ExcludedX400Addresses

	// PermittedDirectoryNames
	// ExcludedDirectoryNames

	// PermittedEdiPartyNames
	// ExcludedEdiPartyNames

	// PermittedURIs
	// ExcludedURIs

	// PermittedRegisteredIDs
	// ExcludedRegisteredIDS

	return nil
}
