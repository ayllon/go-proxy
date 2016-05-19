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
	"crypto/x509"
)

// getProxyType returns the proxy type of cert
func getProxyType(cert *x509.Certificate) ProxyType {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ProxyCertInfo) {
			return ProxyTypeRFC3820
		} else if ext.Id.Equal(ProxyCertInfoLegacy) {
			return ProxyTypeDraft
		}
	}
	if cert.Subject.CommonName == "proxy" {
		return ProxyTypeLegacy
	}
	return ProxyTypeNoProxy
}

// isProxy checks if cert is a proxy certificate.
func isProxy(cert *x509.Certificate) bool {
	return getProxyType(cert) != ProxyTypeNoProxy
}

// getEndUserCertificate returns the end user original certificate.
func getEndUserCertificate(proxy *X509Proxy) *x509.Certificate {
	if proxy.ProxyType == ProxyTypeNoProxy {
		return proxy.Certificate
	}
	for _, cert := range proxy.Chain {
		if !isProxy(cert) {
			return cert
		}
	}
	return nil
}

// getIdentity returns the original user identity.
func getIdentity(proxy *X509Proxy) (string, error) {
	cert := getEndUserCertificate(proxy)
	if cert == nil {
		return "", ErrMalformedProxy
	}
	return NameRepr(cert.Subject), nil
}
