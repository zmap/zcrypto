// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Use non-cgo on Darwin to prevent duplicate symbols on cgo

//go:build !arm && !arm64 && !ios
// +build !arm,!arm64,!ios

package x509

func loadSystemRoots() (*CertPool, error) {
	return execSecurityRoots()
}
