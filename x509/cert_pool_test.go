// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSubjects(t *testing.T) {
	certs := makeRandomCertsForPool(1000)
	pool := NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	subjects := pool.Subjects()
	for i := range subjects {
		if bytes.Compare(subjects[i], pool.Certificates()[i].RawSubject) != 0 {
			t.Fail()
		}
	}
}

func TestSumAndContains(t *testing.T) {
	certs1 := makeRandomCertsForPool(1000)
	pool1 := NewCertPool()
	for _, c := range certs1 {
		pool1.AddCert(c)
	}
	certs2 := makeRandomCertsForPool(1000)
	pool2 := NewCertPool()
	for _, c := range certs2 {
		pool2.AddCert(c)
	}
	sum := pool1.Sum(pool2)
	for _, c := range pool1.Certificates() {
		if !sum.Contains(c) {
			t.Fail()
		}
	}
	for _, c := range sum.Certificates() {
		if !pool1.Contains(c) && !pool2.Contains(c) {
			t.Fail()
		}
	}
}

func TestSumAndSize(t *testing.T) {
	certs1 := makeRandomCertsForPool(1000)
	pool1 := NewCertPool()
	for _, c := range certs1 {
		pool1.AddCert(c)
	}
	certs2 := makeRandomCertsForPool(1000)
	pool2 := NewCertPool()
	for _, c := range certs2 {
		pool2.AddCert(c)
	}
	sum := pool1.Sum(pool2)
	if sum.Size() != 2000 {
		t.Fail()
	}
}

func TestSumAndCovers(t *testing.T) {
	certs1 := makeRandomCertsForPool(1000)
	pool1 := NewCertPool()
	for _, c := range certs1 {
		pool1.AddCert(c)
	}
	certs2 := makeRandomCertsForPool(1000)
	pool2 := NewCertPool()
	for _, c := range certs2 {
		pool2.AddCert(c)
	}
	sum := pool1.Sum(pool2)
	if !sum.Covers(pool1) || !sum.Covers(pool2) {
		t.Fail()
	}
	if pool1.Covers(sum) || pool2.Covers(sum) {
		t.Fail()
	}
}

func makeRandomCertsForPool(n int) []*Certificate {
	out := make([]*Certificate, 0, n)
	for i := 0; i < n; i++ {
		c := new(Certificate)
		c.FingerprintSHA256 = make([]byte, 256/8)
		if _, err := rand.Read(c.FingerprintSHA256); err != nil {
			panic(err)
		}
		c.RawSubject = make([]byte, 1)
		if _, err := rand.Read(c.RawSubject); err != nil {
			panic(err)
		}
		c.SubjectKeyId = make([]byte, 2)
		if _, err := rand.Read(c.SubjectKeyId); err != nil {
			panic(err)
		}
		c.Raw = make([]byte, 2048)
		if _, err := rand.Read(c.Raw); err != nil {
			panic(err)
		}
		out = append(out, c)
	}
	return out
}

func doBench(b *testing.B, certs []*Certificate) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
	}
}

func BenchmarkCertPoolAdd10(b *testing.B) {
	certs := makeRandomCertsForPool(10)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd100(b *testing.B) {
	certs := makeRandomCertsForPool(100)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd200(b *testing.B) {
	certs := makeRandomCertsForPool(200)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd300(b *testing.B) {
	certs := makeRandomCertsForPool(300)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd400(b *testing.B) {
	certs := makeRandomCertsForPool(400)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd500(b *testing.B) {
	certs := makeRandomCertsForPool(500)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd600(b *testing.B) {
	certs := makeRandomCertsForPool(600)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd700(b *testing.B) {
	certs := makeRandomCertsForPool(700)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd800(b *testing.B) {
	certs := makeRandomCertsForPool(800)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd900(b *testing.B) {
	certs := makeRandomCertsForPool(900)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd1000(b *testing.B) {
	certs := makeRandomCertsForPool(1000)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd10000(b *testing.B) {
	certs := makeRandomCertsForPool(10000)
	doBench(b, certs)
}

func BenchmarkCertPoolAdd100000(b *testing.B) {
	certs := makeRandomCertsForPool(100000)
	doBench(b, certs)
}
