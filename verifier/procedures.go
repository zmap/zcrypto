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

// TODO: Implement these as the VerifyProcedure interface expands.

// VerifyProcedureNSS implements the VerifyProcedure interface for NSS.
type VerifyProcedureNSS struct{}

// VerifyProcedureMicrosoft implements the VerifyProcedure interface for
// Microsoft.
type VerifyProcedureMicrosoft struct{}

// VerifyProcedureApple implements the VerifyProcedure interface for Apple.
type VerifyProcedureApple struct{}

// VerifyProcedureJava implements the VerifyProcedure interface for Java.
type VerifyProcedureJava struct{}

// VerifyProcedureGoogleCTPrimary implements the VerifyProcedure interface for
// the primary Google CT servers.
type VerifyProcedureGoogleCTPrimary struct{}
