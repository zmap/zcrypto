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

// Built-in verifiers representing common root stores.
var (
	// NSS is a Verifier mimicking the validation used in Firefox.
	NSS Verifier

	// Microsoft is a Verifier mimicking the validation in Windows 10 SChannel.
	Microsoft Verifier

	// Apple is a Verifier mimicking the validation in OS X Sierra SecureTransport.
	Apple Verifier

	// Java is a Verifier mimicking the validation in Java 8 javax.net.ssl.
	Java Verifier

	//. GoogleCTPrimary is a Verifier mimicking the validation for the primary
	//Google CT servers (e.g. Pilot).
	GoogleCTPrimary Verifier
)

// InitializeNSS sets up the built-in NSS Verifier.
func InitializeNSS(roots, intermediates *x509.CertPool) {
	NSS.Roots = roots
	NSS.Intermediates = intermediates
	NSS.VerifyProcedure = &VerifyProcedureNSS{}
}

// InitializeMicrosoft sets up the built-in Microsoft Verifier.
func InitializeMicrosoft(roots, intermediates *x509.CertPool) {
	Microsoft.Roots = roots
	Microsoft.Intermediates = intermediates
	Microsoft.VerifyProcedure = &VerifyProcedureMicrosoft{}
}

// InitializeApple sets up the built-in Apple Verifier.
func InitializeApple(roots, intermediates *x509.CertPool) {
	Apple.Roots = roots
	Apple.Intermediates = intermediates
	Apple.VerifyProcedure = &VerifyProcedureApple{}
}

// InitializeJava sets up the built-in Java Verifier.
func InitializeJava(roots, intermediates *x509.CertPool) {
	Java.Roots = roots
	Java.Intermediates = intermediates
	Java.VerifyProcedure = &VerifyProcedureJava{}
}

// InitializeGoogleCTPrimary sets up the built-in Google CT Primary verifier.
func InitializeGoogleCTPrimary(roots, intermediates *x509.CertPool) {
	GoogleCTPrimary.Roots = roots
	Java.Intermediates = intermediates
	Java.VerifyProcedure = &VerifyProcedureGoogleCTPrimary{}
}
