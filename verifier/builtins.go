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

// NewNSS returns a new verifier mimicking NSS.
func NewNSS(pki *x509.Graph) (nss *Verifier) {
	nss = NewVerifier(pki, &VerifyProcedureNSS{})
	return
}

// NewMicrosoft returns a new verifier mimicking Microsoft SChannel.
func NewMicrosoft(pki *x509.Graph) (microsoft *Verifier) {
	microsoft = NewVerifier(pki, &VerifyProcedureMicrosoft{})
	return
}

// NewApple returns a new verifier mimicking Apple SecureTransport.
func NewApple(pki *x509.Graph) (apple *Verifier) {
	apple = NewVerifier(pki, &VerifyProcedureApple{})
	return
}

// NewJava returns a new verifier mimicking javax.net.ssl.
func NewJava(pki *x509.Graph) (java *Verifier) {
	java = NewVerifier(pki, &VerifyProcedureJava{})
	return
}

// NewGoogleCTPrimary returns a new verifier mimicking the behavior of the
// primary Google CT logs (e.g. Pilot).
func NewGoogleCTPrimary(pki *x509.Graph) (gct *Verifier) {
	gct = NewVerifier(pki, &VerifyProcedureGoogleCTPrimary{})
	return
}
