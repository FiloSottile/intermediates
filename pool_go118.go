// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build go1.18 && !go1.19
// +build go1.18,!go1.19

package intermediates

import (
	"crypto/sha256"
	"crypto/x509"
	"unsafe"
)

type sum224 [sha256.Size224]byte

type certPool struct {
	byName     map[string][]int // cert.RawSubject => index into lazyCerts
	lazyCerts  []lazyCert
	haveSum    map[sum224]bool
	systemPool bool
}

type lazyCert struct {
	rawSubject []byte
	getCert    func() (*x509.Certificate, error)
}

func copyCertPool(in *x509.CertPool) *x509.CertPool {
	s := (*certPool)(unsafe.Pointer(in))
	p := &certPool{
		byName:     make(map[string][]int, len(s.byName)),
		lazyCerts:  make([]lazyCert, len(s.lazyCerts)),
		haveSum:    make(map[sum224]bool, len(s.haveSum)),
		systemPool: s.systemPool,
	}
	for k, v := range s.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	for k := range s.haveSum {
		p.haveSum[k] = true
	}
	copy(p.lazyCerts, s.lazyCerts)
	return (*x509.CertPool)(unsafe.Pointer(p))
}
