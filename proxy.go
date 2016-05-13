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
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"time"
)

type ProxyType int

var (
	VomsExtOid             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8005, 100, 100, 5}
	VomsAttrOid            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8005, 100, 100, 4}
	ProxyCertInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	ProxyCertInfoLegacy    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 222}
	ProxyPolicyAnyLanguage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 0}
	ProxyPolicyInheritAll  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 1}
	ProxyPolicyIndependent = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 2}

	ErrMalformedProxy   = errors.New("Malformed proxy")
	ErrModulusMismatch  = errors.New("Modulus mismatch")
)

const (
	ProxyTypeNoProxy = ProxyType(0)
	ProxyTypeLegacy  = ProxyType(1)
	ProxyTypeDraft   = ProxyType(2)
	ProxyTypeRFC3820 = ProxyType(3)
)

type (
	// VoExtension holds basic information about the Vo extensions of a proxy.
	VomsAttribute struct {
		Subject             string
		Issuer              string
		Vo                  string
		Fqan                string
		NotBefore, NotAfter time.Time
		PolicyAuthority     string
	}

	// Proxy holds an X509 proxy.
	X509Proxy struct {
		// Actual data
		Certificate *x509.Certificate
		Key         *rsa.PrivateKey
		Chain       []*x509.Certificate
		// Convenience fields
		ProxyType      ProxyType
		Subject        string
		Issuer         string
		Identity       string
		DelegationId   string
		VomsAttributes []VomsAttribute
	}
)

// Lifetime returns the remaining life of the Vo extension.
func (v *VomsAttribute) Lifetime() time.Duration {
	return v.NotAfter.Sub(time.Now())
}

// Expired returns true if the VO extension has expired.
func (v *VomsAttribute) Expired() bool {
	return v.Lifetime() < 0
}

// Lifetime returns the remaining life of the proxy.
func (p *X509Proxy) Lifetime() time.Duration {
	return p.Certificate.NotAfter.Sub(time.Now())
}

// Expired returns true if the proxy has expired, or if any of its Vo extensions has
func (p *X509Proxy) Expired() bool {
	if p.Lifetime() < 0 {
		return true
	}

	for _, vo := range p.VomsAttributes {
		if vo.Expired() {
			return true
		}
	}

	return false
}

// Decode loads a X509 proxy from a string in memory.
// Returns a pointer to a X509Proxy holding basic information about the proxy, as valid timestamps,
// VO extensions, etc.
func (p *X509Proxy) Decode(raw []byte) (err error) {
	p.Chain = make([]*x509.Certificate, 0, 10)

	for block, remaining := pem.Decode(raw); block != nil; block, remaining = pem.Decode(remaining) {
		switch block.Type {
		case "RSA PRIVATE KEY":
			p.Key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
				break
			} else if p.Certificate == nil {
				p.Certificate = cert
			} else {
				p.Chain = append(p.Chain, cert)
			}
		default:
			err = ErrMalformedProxy
		}

		if err != nil {
			return
		}
	}

	if p.Certificate == nil {
		err = ErrMalformedProxy
		return
	}

	if err = p.parseExtensions(p.Certificate); err != nil {
		return
	}
	for _, cert := range p.Chain {
		if err = p.parseExtensions(cert); err != nil {
			return
		}
	}

	p.ProxyType = getProxyType(p.Certificate)
	p.DelegationId = calculateDelegationId(p)
	p.Subject = NameRepr(p.Certificate.Subject)
	p.Issuer = NameRepr(p.Certificate.Issuer)
	p.Identity, err = getIdentity(p)

	return

}

// DecodeFromFile loads a X509 proxy from a file.
// Returns a pointer to a X509Proxy holding basic information about the proxy, as valid timestamps,
// VO extensions, etc.
func (p *X509Proxy) DecodeFromFile(path string) (err error) {
	if _, err = os.Stat(path); err != nil {
		return
	}

	var pem []byte
	if pem, err = ioutil.ReadFile(path); err != nil {
		return
	}

	return p.Decode(pem)
}

// Encode returns the PEM version of the proxy.
func (p *X509Proxy) Encode() []byte {
	full := make([]byte, 0)

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.Certificate.Raw,
	})
	full = append(full, pemCert...)

	if p.Key != nil {
		pemKey := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(p.Key),
		})
		full = append(full, pemKey...)
	}

	for _, cert := range p.Chain {
		pemChain := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		full = append(full, pemChain...)
	}

	return full
}
