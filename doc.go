/*
 * ZCrypto Copyright 2019 Regents of the University of Michigan
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

// ZCrypto is a research and data collection cryptography library, designed to
// be used for measuring and analyzing cryptographic deployments on the
// Internet. It is largely centered around the WebPKI.
//
// ZCrypto contains forks of the Golang X.509 and TLS libraries that speak old
// TLS versions, deprecated ciphers. ZCrypto provides more lenient and open
// access to X.509 certificates and TLS handshake state than its standard
// library counterparts.
//
// ZCrypto also contains a custom X.509 chain builder, designed for bulk chain
// building across large sets of certificates.
package zcrypto
