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
	"errors"
	"io/ioutil"
	"path"
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
	eec := getEndUserCertificate(p)
	if eec == nil {
		return errors.New("Can not find the End Entity Certificate")
	}

	if _, err := eec.Verify(options); err != nil {
		return err
	}

	// TODO: Once the EEC is verified, we validate the proxy chain
	return nil
}
