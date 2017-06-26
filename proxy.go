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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

// Type is the detected type of the proxy. It can be No Proxy, Legacy, Draft or RFC.
type Type int

// Proxy types.
const (
	TypeNoProxy = Type(0)
	TypeLegacy  = Type(1)
	TypeDraft   = Type(2)
	TypeRFC3820 = Type(3)
)

type (
	// VomsAttribute holds basic information about the Vo extensions of a proxy.
	VomsAttribute struct {
		Raw []byte

		Subject             pkix.Name
		Issuer              pkix.Name
		Vo                  string
		Fqan                string
		NotBefore, NotAfter time.Time
		PolicyAuthority     string

		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
		Chain              []*x509.Certificate
	}

	// X509Proxy holds an X509 proxy.
	X509Proxy struct {
		x509.Certificate
		PrivateKey     *rsa.PrivateKey
		Chain          []*x509.Certificate
		ProxyType      Type
		Issuer         pkix.Name
		Identity       pkix.Name
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

// DelegationID returns the delegation id corresponding to the proxy.
func (p *X509Proxy) DelegationID() string {
	hash := sha1.New()
	hash.Write([]byte(NameRepr(&p.Subject)))
	for _, vo := range p.VomsAttributes {
		hash.Write([]byte(vo.Fqan))
	}
	data := make([]byte, 0, 20)
	data = hash.Sum(data)
	return fmt.Sprintf("%x", data[:8])
}

// Decode loads a X509 proxy from a string in memory.
// Returns a pointer to a X509Proxy holding basic information about the proxy, as valid timestamps,
// VO extensions, etc.
func (p *X509Proxy) Decode(raw []byte) (err error) {
	chain := make([]*x509.Certificate, 0, 10)

	for block, remaining := pem.Decode(raw); block != nil; block, remaining = pem.Decode(remaining) {
		switch block.Type {
		case "PRIVATE KEY":
			var priv interface{}
			var ok bool
			if priv, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return
			}
			if p.PrivateKey, ok = priv.(*rsa.PrivateKey); !ok {
				return x509.ErrUnsupportedAlgorithm
			}
		case "RSA PRIVATE KEY":
			p.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
				break
			} else {
				chain = append(chain, cert)
			}
		default:
			err = fmt.Errorf("Unknown block type: %s", block.Type)
		}

		if err != nil {
			return
		}
	}

	if len(chain) == 0 {
		err = fmt.Errorf("Missing certificate")
		return
	}

	return p.InitFromCertificates(chain)
}

// InitFromCertificates initializes the proxy from a x509 certificate
func (p *X509Proxy) InitFromCertificates(chain []*x509.Certificate) (err error) {
	p.Certificate, p.Chain = *chain[0], chain[1:]

	if err = p.parseExtensions(&p.Certificate); err != nil {
		return
	}
	for _, cert := range p.Chain {
		if err = p.parseExtensions(cert); err != nil {
			return
		}
	}
	p.ProxyType = getProxyType(&p.Certificate)
	p.Subject = p.Certificate.Subject
	p.Issuer = p.Certificate.Issuer
	p.Identity, err = p.getIdentity()

	// For RFC proxies, need to remove the proxyCertInfoOid from the unhandled critical extensions,
	// since we already have
	removeProxyCertInfo(&p.Certificate, proxyCertInfoOid)
	for _, c := range p.Chain {
		removeProxyCertInfo(c, proxyCertInfoOid)
	}

	return
}

// drop the proxyCertInfoOid critical extension
func removeProxyCertInfo(c *x509.Certificate, id asn1.ObjectIdentifier) {
	index := -1
	for i := range c.UnhandledCriticalExtensions {
		if c.UnhandledCriticalExtensions[i].Equal(id) {
			index = i
			break
		}
	}
	if index >= 0 {
		c.UnhandledCriticalExtensions = append(
			c.UnhandledCriticalExtensions[:index], c.UnhandledCriticalExtensions[index+1:]...,
		)
	}
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

// DecodeFromFiles loads a X509 proxy from two files with the cert and the key.
// Returns a pointer to a X509Proxy holding basic information about the proxy, as valid timestamps,
// VO extensions, etc.
func (p *X509Proxy) DecodeFromFiles(cert string, key string) (err error) {
	if cert == key {
		return p.DecodeFromFile(cert)
	}

	if _, err = os.Stat(cert); err != nil {
		return
	}
	if _, err = os.Stat(key); err != nil {
		return
	}

	var certPem, keyPem []byte
	if certPem, err = ioutil.ReadFile(cert); err != nil {
		return
	}
	if keyPem, err = ioutil.ReadFile(key); err != nil {
		return
	}

	return p.Decode(append(certPem, keyPem...))
}

// Encode returns the PEM version of the proxy.
func (p *X509Proxy) Encode() []byte {
	var full []byte

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.Certificate.Raw,
	})
	full = append(full, pemCert...)

	if p.PrivateKey != nil {
		pemKey := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(p.PrivateKey),
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

// getProxyType returns the proxy type of cert
func getProxyType(cert *x509.Certificate) Type {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(proxyCertInfoOid) {
			return TypeRFC3820
		} else if ext.Id.Equal(proxyCertInfoLegacyOid) {
			return TypeDraft
		}
	}
	if cert.Subject.CommonName == "proxy" {
		return TypeLegacy
	}
	return TypeNoProxy
}

// isProxy checks if cert is a proxy certificate.
func isProxy(cert *x509.Certificate) bool {
	return getProxyType(cert) != TypeNoProxy
}

// getEndUserCertificate returns the end user original certificate.
func (p *X509Proxy) getEndUserCertificate() *x509.Certificate {
	if p.ProxyType == TypeNoProxy {
		return &p.Certificate
	}
	for _, cert := range p.Chain {
		if !isProxy(cert) {
			return cert
		}
	}
	return nil
}

// getIdentity returns the original user identity.
func (p *X509Proxy) getIdentity() (pkix.Name, error) {
	cert := p.getEndUserCertificate()
	if cert == nil {
		return pkix.Name{}, errors.New("Could not get the end user certificate")
	}
	return cert.Subject, nil
}

// getProxyCertInfo return the ProxyCertInfo extension
func getProxyCertInfo(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(proxyCertInfoOid) {
			return &ext
		}
	}
	return nil
}
