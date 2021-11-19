// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package intermediates_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"filippo.io/intermediates"
)

func ExampleVerifyConnection() {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection:   intermediates.VerifyConnection,
	}

	c := &http.Client{Transport: tr, Timeout: 1 * time.Minute}
	r, err := c.Get("https://incomplete-chain.badssl.com")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()
	fmt.Println(r.StatusCode)
	// Output: 200
}
