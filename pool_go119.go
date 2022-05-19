// Copyright 2022 Filippo Valsorda
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build go1.19
// +build go1.19

package intermediates

import "crypto/x509"

func copyCertPool(in *x509.CertPool) *x509.CertPool {
	return in.Clone()
}
