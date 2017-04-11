// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"errors"
	"time"
)

// Validation stores different validation levels for a given certificate
type Validation struct {
	Domain          string
	ValidChain      bool
	ValidationError error
	MatchesDomain   bool
	NameError       error
}

type auxValidation struct {
	BrowserTrusted bool   `json:"browser_trusted"`
	BrowserError   string `json:"browser_error,omitempty"`
	MatchesDomain  bool   `json:"matches_domain,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface
func (v *Validation) MarshalJSON() ([]byte, error) {
	aux := new(auxValidation)
	aux.BrowserTrusted = v.ValidChain
	aux.BrowserError = v.ValidationError.Error()
	aux.MatchesDomain = v.MatchesDomain
	return json.Marshal(aux)
}

// UnmarshalJSON implements the json.Marshaler interface
func (v *Validation) UnmarshalJSON(b []byte) error {
	aux := new(auxValidation)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	v.ValidChain = aux.BrowserTrusted
	if len(aux.BrowserError) > 0 {
		v.ValidationError = errors.New(aux.BrowserError)
	}
	v.MatchesDomain = aux.MatchesDomain
	return nil
}

// ValidateWithStupidDetail fills out a Validation struct given a leaf
// certificate and intermediates / roots. If opts.DNSName is set, then it will
// also check if the domain matches.
func (c *Certificate) ValidateWithStupidDetail(opts VerifyOptions) (chains [][]*Certificate, validation *Validation, err error) {

	// Manually set the time, so that all verifies we do get the same time
	if opts.CurrentTime.IsZero() {
		opts.CurrentTime = time.Now()
	}

	// XXX: Don't pass a KeyUsage to the Verify API
	opts.KeyUsages = nil
	domain := opts.DNSName
	opts.DNSName = ""

	out := new(Validation)
	out.Domain = domain

	if chains, _, _, err = c.Verify(opts); err == nil {
		out.ValidationError = err
	} else {
		out.ValidChain = true
	}

	if domain != "" {
		if err = c.VerifyHostname(domain); err != nil {
			out.MatchesDomain = false
			out.NameError = err
		} else {
			out.MatchesDomain = true
		}
	}
	validation = out

	return
}
