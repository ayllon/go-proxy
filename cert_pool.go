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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

type (

	// CertPool is a set of certificates and CRLs.
	CertPool struct {
		*x509.CertPool
		Crls     map[string]*pkix.CertificateList
		CaByHash map[string]*x509.Certificate
	}
)

// nameHash returns a hash of the pkix.Name
func nameHash(name *pkix.Name) string {
	hash := sha1.New()
	hash.Write([]byte(NameRepr(name)))
	rawhash := make([]byte, 0, 20)
	rawhash = hash.Sum(rawhash)
	return fmt.Sprintf("%x", rawhash)
}

// AppendFromPEM appends certificates and/or revocations lists from the passed raw PEM data
func (pool *CertPool) AppendFromPEM(data []byte, loadCrls bool) error {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				pool.AddCert(cert)
				pool.CaByHash[nameHash(&cert.Subject)] = cert
			}
		case "X509 CRL":
			if loadCrls {
				if crl, err := x509.ParseCRL(block.Bytes); err == nil {
					name := pkix.Name{}
					name.FillFromRDNSequence(&crl.TBSCertList.Issuer)
					pool.Crls[nameHash(&name)] = crl
				}
			}
		}
	}
	return nil
}

// LoadCAPath loads the certificates stored under path into a cert-pool
func LoadCAPath(capath string, loadCrls bool) (roots *CertPool, err error) {
	roots = &CertPool{
		CertPool: x509.NewCertPool(),
		Crls:     make(map[string]*pkix.CertificateList),
		CaByHash: make(map[string]*x509.Certificate),
	}

	var entries []os.FileInfo
	entries, err = ioutil.ReadDir(capath)
	for _, file := range entries {
		if !file.IsDir() {
			data, ferr := ioutil.ReadFile(path.Join(capath, file.Name()))
			if ferr == nil {
				roots.AppendFromPEM(data, loadCrls)
			} else if err == nil {
				err = ferr
			}
		}
	}

	return
}
