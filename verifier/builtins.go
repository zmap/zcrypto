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
	Java.PKI = x509.NewGraph()
	for _, c := range roots.Certificates() {
		Java.PKI.AddRoot(c)
	}
	for _, c := range intermediates.Certificates() {
		Java.PKI.AddCert(c)
	}
	Java.VerifyProcedure = &VerifyProcedureNSS{}
}

// InitializeMicrosoft sets up the built-in Microsoft Verifier.
func InitializeMicrosoft(roots, intermediates *x509.CertPool) {
	Microsoft.PKI = x509.NewGraph()
	for _, c := range roots.Certificates() {
		Microsoft.PKI.AddRoot(c)
	}
	for _, c := range intermediates.Certificates() {
		Microsoft.PKI.AddCert(c)
	}
	Microsoft.VerifyProcedure = &VerifyProcedureMicrosoft{}
}

// InitializeApple sets up the built-in Apple Verifier.
func InitializeApple(roots, intermediates *x509.CertPool) {
	Apple.PKI = x509.NewGraph()
	for _, c := range roots.Certificates() {
		Apple.PKI.AddRoot(c)
	}
	for _, c := range intermediates.Certificates() {
		Apple.PKI.AddCert(c)
	}
	Apple.VerifyProcedure = &VerifyProcedureApple{}
}

// InitializeJava sets up the built-in Java Verifier.
func InitializeJava(roots, intermediates *x509.CertPool) {
	Java.PKI = x509.NewGraph()
	for _, c := range roots.Certificates() {
		Java.PKI.AddRoot(c)
	}
	for _, c := range intermediates.Certificates() {
		Java.PKI.AddCert(c)
	}
	Java.VerifyProcedure = &VerifyProcedureJava{}
}

// InitializeGoogleCTPrimary sets up the built-in Google CT Primary verifier.
func InitializeGoogleCTPrimary(roots, intermediates *x509.CertPool) {
	GoogleCTPrimary.PKI = x509.NewGraph()
	for _, c := range roots.Certificates() {
		GoogleCTPrimary.PKI.AddRoot(c)
	}
	for _, c := range intermediates.Certificates() {
		GoogleCTPrimary.PKI.AddCert(c)
	}
	GoogleCTPrimary.VerifyProcedure = &VerifyProcedureGoogleCTPrimary{}
}
