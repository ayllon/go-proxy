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
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"reflect"
	"time"
)

// LoadCAPath loads the certificates stored under path into a cert-pool
func LoadCAPath(capath string) (roots *x509.CertPool, err error) {
	roots = x509.NewCertPool()

	entries, err := ioutil.ReadDir(capath)
	for _, file := range entries {
		if !file.IsDir() {
			data, ferr := ioutil.ReadFile(path.Join(capath, file.Name()))
			if ferr == nil {
				roots.AppendCertsFromPEM(data)
			} else if err == nil {
				err = ferr
			}
		}
	}

	return
}

// Verify tries to verify if the proxy is trustworthy
// If it is, it will return nil, an error otherwise.
// TODO: Verify VO extensions
func (p *X509Proxy) Verify(roots *x509.CertPool) error {
	options := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for _, intermediate := range p.Chain {
		options.Intermediates.AddCert(intermediate)
	}

	// From RFC3820, verify first the End Entity Certificate
	index, eec := getEndUserCertificate(p)
	if eec == nil {
		return errors.New("Can not find the End Entity Certificate")
	}

	if _, err := eec.Verify(options); err != nil {
		return err
	}

	// Once the EEC is verified, we validate the proxy chain
	return verifyProxyChain(p, index, eec)
}

// Follow the proxy chain until the EEC
// See https://tools.ietf.org/html/rfc3820#section-4
func verifyProxyChain(p *X509Proxy, eecIndex int, eec *x509.Certificate) error {
	maxPathLen := eecIndex
	parent := eec

	for i := eecIndex - 1; i >= 0; i-- {
		c := p.Chain[i]

		// a.1 The certificate was signed by the parent
		if err := parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			return err
		}
		// a.2 The certificate validity period includes the current time
		now := time.Now()
		if c.NotBefore.Sub(now) > 0 || c.NotAfter.Sub(now) < 0 {
			return x509.CertificateInvalidError{c, x509.Expired}
		}
		// a.3 The certificate issuer name is the parent issuer name
		if !reflect.DeepEqual(c.Issuer, parent.Subject) {
			issuerSubject := NameRepr(c.Issuer)
			parentSubject := NameRepr(parent.Subject)
			return fmt.Errorf(
				"Issuer does not match parent subject: %s != %s", issuerSubject, parentSubject,
			)
		}
		// a.4 The certificate subject name is the issuer name plus a CN appended
		// TODO

		// b
		proxyCertInfoExt := getProxyCertInfo(c)
		if proxyCertInfoExt == nil {
			return errors.New("Only RFC3820 proxies are supported for validation")
		}
		if !proxyCertInfoExt.Critical {
			return errors.New("ProxyCertInfo extension must be critical")
		}
		proxyCertInfo := proxyCertInfoExtension{}
		if _, err := asn1.Unmarshal(proxyCertInfoExt.Value, &proxyCertInfo); err != nil {
			return err
		}

		// b.1 pCPathLenConstraint
		if proxyCertInfo.PCPathLenConstraint > 0 && proxyCertInfo.PCPathLenConstraint < maxPathLen {
			maxPathLen = proxyCertInfo.PCPathLenConstraint
		}

		// b.2 TODO
		// c TODO
		// d TODO

		if maxPathLen <= 0 {
			return errors.New("Max proxy chain length reached")
		}
		maxPathLen -= 1
	}

	return nil
}
