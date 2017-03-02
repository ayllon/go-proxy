/*
 * Copyright (c) CERN 2016
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package proxy

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"testing"
	"time"
)

// Test the creation of a proxy request.
func TestCreateProxyRequest(t *testing.T) {
	var r X509ProxyRequest

	if err := r.Init(2048, x509.SHA256WithRSA); err != nil {
		t.Fatal(err)
	}
	if r.Key.N.BitLen() != 2048 {
		t.Fatal("Wrong bit size")
	}
	if r.Request.PublicKey.(*rsa.PublicKey).N.Cmp(r.Key.N) != 0 {
		t.Fatal("Request and private key do not match")
	}
}

// Test the creation of a new proxy.
func TestNewProxy(t *testing.T) {
	var r X509ProxyRequest
	var p X509Proxy

	if err := r.Init(2048, x509.SHA256WithRSA); err != nil {
		t.Fatal(err)
	}

	certRaw, err := ioutil.ReadFile("test-samples/SigningCert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decode(certRaw); err != nil {
		t.Fatal(err)
	}

	nested, err := p.SignRequest(&r, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if nested == nil {
		t.Fatal("New proxy is nil")
	}
	if nested.PrivateKey != nil {
		t.Fatal("The private key must not be set")
	}

	if nested.Certificate.PublicKey.(*rsa.PublicKey).N.Cmp(r.Key.N) != 0 ||
		nested.Certificate.PublicKey.(*rsa.PublicKey).E != r.Key.E {
		t.Fatal("New proxy public key does not match the private key used to sign the request")
	}
	if !r.Matches(nested) {
		t.Fatal("Matches method must return true here")
	}

	if bytes.Compare(nested.Certificate.RawIssuer, p.Certificate.RawSubject) != 0 {
		t.Fatal("The issuer of the new proxy is not the original proxy")
	}

	if nested.Certificate.NotAfter.After(p.Certificate.NotAfter) {
		t.Fatal("The new proxy can not expire after the signing proxy")
	}
	if nested.Certificate.NotBefore.Before(p.Certificate.NotBefore) {
		t.Fatal("The new proxy can not start before the signing proxy")
	}
	if reflect.DeepEqual(nested.Subject, p.Subject) {
		t.Fatal("The proxy can not have the same subject as the signing proxy")
	}

	diff := nameDiff(&p.Subject, &nested.Subject)
	if len(diff) != 1 || !diff[0].Type.Equal(commonNameOid) {
		t.Fatalf("The proxy subject does not extend the signing proxy subject:\n\t%s\n\t%s\n",
			nested.Subject, p.Subject)
	}
	if bytes.Compare(nested.Chain[0].RawSubject, p.Certificate.RawSubject) != 0 {
		t.Fatal("The first certificate in the chain must be the signing certificate")
	}
}
