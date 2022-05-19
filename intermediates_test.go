// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package intermediates

import (
	"crypto/tls"
	"testing"
)

func TestBadSSL(t *testing.T) {
	t.Skip("badssl.com certificates are currently expired")
	c, err := tls.Dial("tcp", "incomplete-chain.badssl.com:443", &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   VerifyConnection,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

func TestIncompleteChain(t *testing.T) {
	c, err := tls.Dial("tcp", "google.com:443", &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			cs.PeerCertificates = cs.PeerCertificates[:1]
			return VerifyConnection(cs)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

func TestCount(t *testing.T) {
	if gotCount := len(Pool().Subjects()); gotCount != expectedCount {
		t.Logf("%s", Pool().Subjects())
		t.Errorf("intermediates: parsed %d certificates, expected %d", gotCount, expectedCount)
	}
}

func TestReuse(t *testing.T) {
	a, b := Pool(), Pool()
	a.AppendCertsFromPEM([]byte(`
-----BEGIN CERTIFICATE-----
MIICDzCCAXigAwIBAgIBADANBgkqhkiG9w0BAQQFADBCMQswCQYDVQQGEwJQTDEf
MB0GA1UEChMWU3R1bm5lbCBEZXZlbG9wZXJzIEx0ZDESMBAGA1UEAxMJbG9jYWxo
b3N0MB4XDTk5MDQwODE1MDkwOFoXDTAwMDQwNzE1MDkwOFowQjELMAkGA1UEBhMC
UEwxHzAdBgNVBAoTFlN0dW5uZWwgRGV2ZWxvcGVycyBMdGQxEjAQBgNVBAMTCWxv
Y2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsVBTLqiSWyPSpwfF
bcEm3L8DTpbVgbVsmkpqe8hJ6sFnpeUxX3Djmwri2evbBYtRC4uQvdakWgzKMO5O
Ro9OQ2bSwxXyAg9FtUvp9iqpdqPH9kUr2ag9lvZfIufV2ws9aEuJfUtPS/t0U2Vf
aHq/1J28v0JonBSzTNFoK1TYissCAwEAAaMVMBMwEQYJYIZIAYb4QgEBBAQDAgZA
MA0GCSqGSIb3DQEBBAUAA4GBAAhYFTngWc3tuMjVFhS4HbfFF/vlOgTu44/rv2F+
ya1mEB93htfNxx3ofRxcjCdorqONZFwEba6xZ8/UujYfVmIGCBy4X8+aXd83TJ9A
eSjTzV9UayOoGtmg8Dv2aj/5iabNeK1Qf35ouvlcTezVZt2ZeJRhqUHcGaE+apCN
TC9Y
-----END CERTIFICATE-----
`))
	if len(a.Subjects()) == len(b.Subjects()) {
		t.Fail()
	}
}
