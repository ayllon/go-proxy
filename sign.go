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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

type (
	proxyCertInfoExtension struct {
		PCPathLenConstraint int `asn1:"optional"`
		ProxyPolicy         proxyPolicy
	}

	proxyPolicy struct {
		PolicyLanguage asn1.ObjectIdentifier
		Policy         []byte `asn1:"optional"`
	}
)

var (
	commonNameOid = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// generateProxySubject returns the new proxy subject depending on the type of the signing proxy
func generateProxySubject(p *X509Proxy, out *pkix.Name) {
	out.Names = append(out.Names, p.Certificate.Subject.Names...)
	out.ExtraNames = append(out.ExtraNames, p.Certificate.Subject.Names...)

	if p.ProxyType == TypeRFC3820 {
		out.ExtraNames = append(out.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  commonNameOid,
			Value: fmt.Sprint(time.Now().Unix()),
		})
	} else {
		out.ExtraNames = append(out.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  commonNameOid,
			Value: "proxy",
		})
	}
}

// SignRequest creates a new delegated proxy signed by this proxy.
// The private key will be missing!
func (p *X509Proxy) SignRequest(req *X509ProxyRequest, lifetime time.Duration) (new *X509Proxy, err error) {
	template := x509.Certificate{}

	template.PublicKey = req.Request.PublicKey
	template.SerialNumber = p.Certificate.SerialNumber
	generateProxySubject(p, &template.Subject)
	template.NotAfter = time.Now().Add(lifetime)
	template.NotBefore = time.Now()
	template.KeyUsage = p.Certificate.KeyUsage
	template.BasicConstraintsValid = true
	template.IsCA = false
	template.MaxPathLen = p.Certificate.MaxPathLen
	template.MaxPathLenZero = p.Certificate.MaxPathLenZero
	template.SignatureAlgorithm = req.Request.SignatureAlgorithm

	if p.Certificate.NotAfter.Before(template.NotAfter) {
		template.NotAfter = p.Certificate.NotAfter
	}

	switch p.ProxyType {
	case TypeRFC3820:
		var data []byte
		data, err = asn1.Marshal(proxyCertInfoExtension{
			ProxyPolicy: proxyPolicy{
				PolicyLanguage: proxyPolicyInheritAllOid,
			},
		})
		if err != nil {
			return
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       proxyCertInfoOid,
			Critical: true,
			Value:    data,
		})
	}

	rawCert, err := x509.CreateCertificate(
		rand.Reader, &template, &p.Certificate, req.Request.PublicKey, p.PrivateKey,
	)
	if err != nil {
		return
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return
	}

	new = &X509Proxy{
		Certificate:    *cert,
		PrivateKey:     nil,
		Chain:          make([]*x509.Certificate, 0, len(p.Chain)+1),
		ProxyType:      p.ProxyType,
		Issuer:         p.Subject,
		Identity:       p.Identity,
		VomsAttributes: make([]VomsAttribute, len(p.VomsAttributes)),
	}
	new.Chain = append(new.Chain, &p.Certificate)
	new.Chain = append(new.Chain, p.Chain...)
	copy(new.VomsAttributes, p.VomsAttributes)
	return
}
