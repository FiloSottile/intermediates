// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package intermediates embeds a list of known unexpired, unrevoked
// intermediate certificates chaining to roots with Websites trust in the
// Mozilla Root Program.
//
// This dataset is useful to establish connections to misconfigured servers that
// fail to provide a full certificate chain but provide a valid, publicly
// trusted end-entity certificate. Some browsers implement similar strategies to
// successfully establish connections to these sites.
//
// Note that this might not be necessary if using the system roots on certain
// operating systems, as the platform verifier might have its own mechanism to
// fetch missing intermediates.
package intermediates

import (
	"compress/flate"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"io"
	"strings"
	"sync"
)

//go:embed intermediates.bin
var compressedPEMPool string

var loadOnce sync.Once
var pool *x509.CertPool

// Pool returns a new x509.CertPool containing a set of known WebPKI
// intermediates chaining to roots in the Mozilla Root Program.
//
// These certificates must not be used as trusted roots, but can be used as the
// Intermediates pool in x509.VerifyOptions.
//
// The returned CertPool can be modified safely, for example to add
// intermediates provided by the server, and multiple invocations return
// distinct CertPools.
func Pool() *x509.CertPool {
	loadOnce.Do(func() {
		r := flate.NewReader(strings.NewReader(compressedPEMPool))
		pemList, _ := io.ReadAll(r)
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(pemList))
	})
	return copyCertPool(pool)
}

// VerifyConnection is a function that can be used as the VerifyConnection
// callback in a tls.Config for a client connection.
//
// It performs the same verification that crypto/tls does by default, but it
// makes use of both the server's intermediates and this package's pool, and it
// disregards the Time and RootCAs fields of tls.Config, using their default
// values: the current time and the system roots.
func VerifyConnection(cs tls.ConnectionState) error {
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: Pool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}
