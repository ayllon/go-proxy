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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
)

type (
	// X509ProxyRequest contains both certificate request and the associated private key.
	X509ProxyRequest struct {
		Request *x509.CertificateRequest
		Key     *rsa.PrivateKey
	}
)

// Init initializes the certificate request and private key, using a key of 'bits', and signed with the given algorithm.
func (r *X509ProxyRequest) Init(bits int, signature x509.SignatureAlgorithm) (err error) {
	if r.Key, err = rsa.GenerateKey(rand.Reader, bits); err != nil {
		return
	}
	reqTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Dummy"},
		},
		Attributes:         nil,
		SignatureAlgorithm: signature,
		Extensions:         nil,
	}
	var csr []byte
	if csr, err = x509.CreateCertificateRequest(rand.Reader, &reqTemplate, r.Key); err != nil {
		return
	}

	r.Request, err = x509.ParseCertificateRequest(csr)
	return
}

// EncodeRequest returns the PEm encoded version of the request.
func (r *X509ProxyRequest) EncodeRequest() []byte {
	if r.Request == nil {
		return make([]byte, 0)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: r.Request.Raw,
	})
}

// EncodeKey returns the PEM encoded version of the private key.
func (r *X509ProxyRequest) EncodeKey() []byte {
	if r.Key == nil {
		return make([]byte, 0)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(r.Key),
	})
}

// Decode decodes a proxy request from both the serialized request and key
func (r *X509ProxyRequest) Decode(req []byte, key []byte) (err error) {
	var reqBlock, keyBlock *pem.Block

	if reqBlock, _ = pem.Decode(req); reqBlock == nil {
		return errors.New("Request is not a valid PEM block")
	} else if reqBlock.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("Expecting CERTIFICATE REQUEST, got %s", reqBlock.Type)
	}
	if r.Request, err = x509.ParseCertificateRequest(reqBlock.Bytes); err != nil {
		return
	}

	if key != nil && len(key) > 0 {
		if keyBlock, _ = pem.Decode(key); keyBlock == nil {
			return errors.New("Private key is not a valid PEM block")
		} else if keyBlock.Type != "RSA PRIVATE KEY" {
			return fmt.Errorf("Expecting RSA PRIVATE KEY, got %s", reqBlock.Type)
		}
		if r.Key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
			return
		}
	}
	return nil
}

// Matches returns true if p is the request signed.
func (r *X509ProxyRequest) Matches(p *X509Proxy) bool {
	return r.Key.N.Cmp(p.Certificate.PublicKey.(*rsa.PublicKey).N) == 0
}
