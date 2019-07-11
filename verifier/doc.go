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

// Package verifier performs detailed certificate validation mimicking the
// behavior of popular browsers and root stores.
//
// It includes a Graph structure than can be used to model the PKI. It
// implements a multigraph in which edges are certificates, and nodes are
// (spki, subject) tuples. The head/source of the edge is the issuer, and the
// tail/destination is the subject. Verifiers walk this graph to perform
// certificate validation.

package verifier
