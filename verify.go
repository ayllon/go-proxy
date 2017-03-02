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
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"time"
)

type (
	// VerifyOptions  contains parameters for X509Proxy.Verify
	VerifyOptions struct {
		Roots       *CertPool
		VomsDir     string
		CurrentTime time.Time // if zero, the current time is used
	}

	// VerificationError is returned when there has been an error validating the main proxy chain
	VerificationError struct {
		hint   error
		nested error
	}

	// VOVerificationError is returned when there has been an error validating the VO extensions
	VOVerificationError struct {
		VerificationError
	}
)

// String returns the human readable representation of a verification error
func (e *VerificationError) Error() string {
	if e.nested != nil {
		return fmt.Sprint("Verification error: ", e.hint, " (", e.nested, ")")
	}
	return fmt.Sprint("Verification error: ", e.hint)
}

// String returns the human readable representation of a VO verification error
func (e *VOVerificationError) Error() string {
	if e.nested != nil {
		return fmt.Sprint("VOMS verification error: ", e.hint, " (", e.nested, ")")
	}
	return fmt.Sprint("VOMS verification error: ", e.hint)
}

// Verify tries to verify if the proxy is trustworthy
// If it is, it will return nil, an error otherwise.
func (p *X509Proxy) Verify(options VerifyOptions) error {
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now()
	}

	x509Options := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         options.Roots.CertPool,
		CurrentTime:   options.CurrentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for _, intermediate := range p.Chain {
		x509Options.Intermediates.AddCert(intermediate)
	}

	// From RFC3820, verify first the End Entity Certificate
	eec := p.getEndUserCertificate()
	if eec == nil {
		return &VerificationError{
			hint: errors.New("Can not find the End Entity Certificate"),
		}
	}

	if _, err := eec.Verify(x509Options); err != nil {
		return &VerificationError{
			hint:   errors.New("Failed to verify the proxy chain"),
			nested: err,
		}
	}

	// EEC seems good, check it is not on the CRL list
	issuerNameHash := nameHash(&eec.Issuer)
	if crl, ok := options.Roots.Crls[issuerNameHash]; ok {
		if crl.HasExpired(options.CurrentTime) {
			return &VerificationError{
				hint: fmt.Errorf("CRL expired for '%s'", NameRepr(&eec.Issuer)),
			}
		} else if ca, ok := options.Roots.CaByHash[issuerNameHash]; !ok {
			return &VerificationError{
				hint: errors.New("Found the Certificate Revocation List, but not its corresponding CA"),
			}
		} else if err := ca.CheckCRLSignature(crl); err != nil {
			return &VerificationError{
				hint:   errors.New("Failed to verify the CRL signature"),
				nested: err,
			}
		}
		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			if revoked.SerialNumber.Cmp(eec.SerialNumber) == 0 {
				return &VerificationError{
					hint: errors.New("Certificate found on the revocation list"),
				}
			}
		}
	}

	// Once the EEC is verified, we validate the proxy chain
	if err := p.verifyProxyChain(eec, options); err != nil {
		return err
	}

	// Verify VO extensions
	return p.verifyVOExtensions(options)
}

// Follow the proxy chain until the EEC
// See https://tools.ietf.org/html/rfc3820#section-4
func (p *X509Proxy) verifyProxyChain(eec *x509.Certificate, options VerifyOptions) error {
	// Build the full chain, including the proxy
	fullChain := make([]*x509.Certificate, 0, len(p.Chain)+1)
	fullChain = append(fullChain, &p.Certificate)
	fullChain = append(fullChain, p.Chain...)

	// Find the EEC on the chain
	eecIndex := 0
	for eecIndex = 0; eecIndex < len(fullChain); eecIndex++ {
		if fullChain[eecIndex].Equal(eec) {
			break
		}
	}
	if eecIndex >= len(fullChain) {
		return &VerificationError{
			hint: errors.New("Could not find the EEC on the chain"),
		}
	}

	// The cert on eecIndex is the EEC certificate, which has been already validated
	// So we start with the next one on the stack
	maxPathLen := eecIndex
	parent := eec
	for i := eecIndex - 1; i >= 0; i-- {
		c := fullChain[i]

		// a.1 The certificate was signed by the parent
		if err := parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			return &VerificationError{
				hint: fmt.Errorf(
					"Certificate '%s' not signed by '%s'", NameRepr(&c.Subject), NameRepr(&parent.Subject),
				),
				nested: err,
			}
		}
		// a.2 The certificate validity period includes the current time
		if options.CurrentTime.Before(c.NotBefore) || options.CurrentTime.After(c.NotAfter) {
			return &VerificationError{
				hint: x509.CertificateInvalidError{c, x509.Expired},
			}
		}
		// a.3 The certificate issuer name is the parent issuer name
		if !reflect.DeepEqual(c.Issuer, parent.Subject) {
			return &VerificationError{
				hint: fmt.Errorf(
					"Issuer does not match parent subject: %s != %s",
					NameRepr(&c.Issuer), NameRepr(&parent.Subject),
				),
			}
		}
		// a.4 The certificate subject name is the issuer name plus a CN appended
		diff := nameDiff(&c.Issuer, &c.Subject)
		if len(diff) != 1 || !diff[0].Type.Equal(cnNameOid) {
			return &VerificationError{
				hint: fmt.Errorf("Invalid subject name: %s (%q)", NameRepr(&c.Subject), diff),
			}
		}

		// b
		proxyCertInfoExt := getProxyCertInfo(c)
		if proxyCertInfoExt == nil {
			return &VerificationError{
				hint: errors.New("Only RFC3820 proxies are supported for validation"),
			}
		}
		if !proxyCertInfoExt.Critical {
			return &VerificationError{
				hint: errors.New("ProxyCertInfo extension must be critical"),
			}
		}
		proxyCertInfo := proxyCertInfoExtension{}
		if _, err := asn1.Unmarshal(proxyCertInfoExt.Value, &proxyCertInfo); err != nil {
			return &VerificationError{
				hint:   errors.New("Failed to unmarshal the proxy cert info extension"),
				nested: err,
			}
		}

		// b.1 pCPathLenConstraint
		if proxyCertInfo.PCPathLenConstraint > 0 && proxyCertInfo.PCPathLenConstraint < maxPathLen {
			maxPathLen = proxyCertInfo.PCPathLenConstraint
		}

		// b.2 TODO
		// c TODO
		// d TODO

		if maxPathLen <= 0 {
			return &VerificationError{
				hint: errors.New("Max proxy chain length reached"),
			}
		}
		maxPathLen--

		// This one has been verified, it becomes the parent of the next one
		parent = c
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
func (p *X509Proxy) verifyVOExtensions(options VerifyOptions) error {
	for _, attr := range p.VomsAttributes {
		if err := verifyVOExtension(attr, options); err != nil {
			return err
		}
	}
	return nil
}

// verifyVOExtension verify a voms attribute
func verifyVOExtension(attr VomsAttribute, options VerifyOptions) error {
	// Verify the signature
	if len(attr.Chain) == 0 {
		return &VOVerificationError{VerificationError{
			hint: fmt.Errorf("Can not find the extension issuer certificate on the proxy"),
		}}
	}

	err := attr.Chain[0].CheckSignature(
		getSignatureAlgorithmFromOID(attr.SignatureAlgorithm.Algorithm), attr.Raw, attr.SignatureValue.Bytes,
	)
	if err != nil {
		return &VOVerificationError{VerificationError{
			hint:   errors.New("Failed to verify the VO extension signature"),
			nested: err,
		}}
	}

	// Verify the extension issuer chain
	intermediates := &x509.CertPool{}
	for _, cert := range attr.Chain[1:] {
		intermediates.AddCert(cert)
	}

	verifycationChains, err := attr.Chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         options.Roots.CertPool,
		CurrentTime:   options.CurrentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return &VOVerificationError{VerificationError{
			hint:   errors.New("Failed to verify the VO extension issuer certificate"),
			nested: err,
		}}
	}

	// Signature is good, and so is the issuer chain
	// But now, the issuer chain must have been configured on the .lsc file
	lscName := attr.Issuer.CommonName + ".lsc"
	lscPath := path.Join(options.VomsDir, attr.Vo, lscName)
	fd, err := os.Open(lscPath)
	if err != nil {
		return &VOVerificationError{VerificationError{
			hint:   errors.New("Coult nout open the .lsc file"),
			nested: err,
		}}
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	for _, cert := range verifycationChains[0] {
		if !scanner.Scan() {
			return &VOVerificationError{VerificationError{
				hint:   errors.New("Reached EOF when reading the lsc file"),
				nested: scanner.Err(),
			}}
		}

		expected := scanner.Text()
		if NameRepr(&cert.Subject) != expected {
			return &VOVerificationError{VerificationError{
				hint: fmt.Errorf(
					"Failed to validate the VOMS attribute chain: %s != %s",
					NameRepr(&cert.Issuer), expected,
				),
			}}
		}
	}

	// Last, but not least, the extension must be still alive
	if options.CurrentTime.Before(attr.NotBefore) {
		return &VOVerificationError{VerificationError{
			hint: fmt.Errorf("VO Extension still not valid"),
		}}
	} else if options.CurrentTime.After(attr.NotAfter) {
		return &VOVerificationError{VerificationError{
			hint: errors.New("VO Extension expired"),
		}}
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
