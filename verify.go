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
	"bufio"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"time"
)

type (
	// VerifyOptions  contains parameters for X509Proxy.Verify
	VerifyOptions struct {
		Roots   *CertPool
		VomsDir string
	}

	// CertPool is a set of trusted certificates.
	CertPool struct {
		certPool       *x509.CertPool
		bySubjectKeyId map[string]*x509.Certificate
		byName         map[string]*x509.Certificate
	}
)

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
func (s *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.certPool.AddCert(cert)
		s.byName[NameRepr(cert.Subject)] = cert
		s.bySubjectKeyId[string(cert.SubjectKeyId)] = cert
		ok = true
	}
	return
}

// LoadCAPath loads the certificates stored under path into a cert-pool
func LoadCAPath(capath string) (roots *CertPool, err error) {
	roots = &CertPool{
		certPool:       x509.NewCertPool(),
		bySubjectKeyId: make(map[string]*x509.Certificate),
		byName:         make(map[string]*x509.Certificate),
	}

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
// TODO: CRL
func (p *X509Proxy) Verify(options *VerifyOptions) error {
	x509Options := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         options.Roots.certPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for _, intermediate := range p.Chain {
		x509Options.Intermediates.AddCert(intermediate)
	}

	// From RFC3820, verify first the End Entity Certificate
	index, eec := p.getEndUserCertificate()
	if eec == nil {
		return errors.New("Can not find the End Entity Certificate")
	}

	if _, err := eec.Verify(x509Options); err != nil {
		return err
	}

	// Once the EEC is verified, we validate the proxy chain
	if err := verifyProxyChain(p, index, eec); err != nil {
		return err
	}

	// Verify VO extensions
	return verifyVOExtensions(p, options)
}

// Follow the proxy chain until the EEC
// See https://tools.ietf.org/html/rfc3820#section-4
func verifyProxyChain(p *X509Proxy, eecIndex int, eec *x509.Certificate) error {
	maxPathLen := eecIndex + 1
	parent := eec

	fullChain := make([]*x509.Certificate, 0, len(p.Chain)+1)
	fullChain = append(fullChain, &p.Certificate)
	fullChain = append(fullChain, p.Chain...)

	for i := eecIndex; i >= 0; i-- {
		c := fullChain[i]

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
			return fmt.Errorf(
				"Issuer does not match parent subject: %s != %s",
				NameRepr(c.Issuer), NameRepr(parent.Subject),
			)
		}
		// a.4 The certificate subject name is the issuer name plus a CN appended
		diff := nameDiff(&c.Issuer, &c.Subject)
		if len(diff) != 1 || !diff[0].Type.Equal(cnNameOid) {
			return fmt.Errorf("Invalid subject name: %s (%q)", NameRepr(c.Subject), diff)
		}

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
		maxPathLen--
	}

	return nil
}

// nameDiff returns the remaining of b once removed, in order, all elements of a
func nameDiff(a, b *pkix.Name) []pkix.AttributeTypeAndValue {
	if len(a.Names) > len(b.Names) {
		return nil
	}

	for i := 0; i < len(b.Names) && i < len(a.Names); i++ {
		if !reflect.DeepEqual(b.Names[i], a.Names[i]) {
			return b.Names[i:]
		}
	}
	return b.Names[len(a.Names):]
}

// verifyVoExtensions verifies the VO extensions present on the proxy
func verifyVOExtensions(p *X509Proxy, options *VerifyOptions) error {
	for _, attr := range p.VomsAttributes {
		if err := verifyVOExtension(attr, options); err != nil {
			return err
		}
	}
	return nil
}

// verifyVOExtension verify a voms attribute
func verifyVOExtension(attr VomsAttribute, options *VerifyOptions) error {
	// Verify the signature
	if len(attr.Chain) == 0 {
		return fmt.Errorf("Can not find the issuer certificate on the proxy")
	}

	err := attr.Chain[0].CheckSignature(
		getSignatureAlgorithmFromOID(attr.SignatureAlgorithm.Algorithm), attr.Raw, attr.SignatureValue.Bytes,
	)
	if err != nil {
		return err
	}

	// Verify the extension issuer chain
	intermediates := &x509.CertPool{}
	for _, cert := range attr.Chain[1:] {
		intermediates.AddCert(cert)
	}

	verifycationChains, err := attr.Chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         options.Roots.certPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}

	// Signature is good, and so is the issuer chain
	// But now, the issuer chain must have been configured on the .lsc file
	lscName := attr.Issuer.CommonName + ".lsc"
	lscPath := path.Join(options.VomsDir, attr.Vo, lscName)
	fd, err := os.Open(lscPath)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	for _, cert := range verifycationChains[0] {
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return scanner.Err()
			}
			return fmt.Errorf("Reached EOF when reading the lsc file")
		}

		expected := scanner.Text()
		if NameRepr(cert.Subject) != expected {
			return fmt.Errorf(
				"Failed to validate the VOMS attribute chain: %s != %s",
				NameRepr(cert.Issuer), expected,
			)
		}
	}

	return nil
}

/*
 * Copied from x509.go, since this is not exposed :(
 */

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return x509.UnknownSignatureAlgorithm
}
