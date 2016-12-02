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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	vomsExtOid                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8005, 100, 100, 5}
	vomsAttrOid               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8005, 100, 100, 4}
	proxyCertInfoOid          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	proxyCertInfoLegacyOid    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3536, 1, 222}
	proxyPolicyAnyLanguageOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 0}
	proxyPolicyInheritAllOid  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 1}
	proxyPolicyIndependentOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 21, 2}
)

type (
	// This is the structure of the extension
	// Defined in RFC 5755
	attributeCertificate struct {
		AcInfo             attributeCertificateInfo
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}

	validityPeriod struct {
		NotBefore, NotAfter time.Time
	}

	attributeCertificateInfo struct {
		Version        int
		Holder         holder
		Issuer         asn1.RawValue
		Signature      pkix.AlgorithmIdentifier
		SerialNumber   *big.Int
		Validity       validityPeriod
		Attributes     []attribute
		IssuerUniqueID asn1.BitString   `asn1:"optional"`
		Extensions     []pkix.Extension `asn1:"optional"`
	}

	holder struct {
		BaseCertificateID issuerSerial     `asn1:"optional,tag:0"`
		EntityName        []asn1.RawValue  `asn1:"optional,tag:1"`
		ObjectDigestInfo  objectDigestInfo `asn1:"optional,tag:2"`
	}

	v2Form struct {
		IssuerName        asn1.RawValue    `asn1:"optional"`
		BaseCertificateID issuerSerial     `asn1:"optional,tag:0"`
		ObjectDigestInfo  objectDigestInfo `asn1:"optional,tag:1"`
	}

	issuerSerial struct {
		Issuer    asn1.RawValue
		Serial    *big.Int
		IssuerUID asn1.BitString `asn1:"optional"`
	}

	objectDigestInfo struct {
		DigestedObjectType asn1.Enumerated
		OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional"`
		DigestAlgorithm    pkix.AlgorithmIdentifier
		ObjectDigest       asn1.BitString
	}

	attribute struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}

	ietfAttrSyntax struct {
		PolicyAuthority asn1.RawValue `asn1:"optional,tag:0"`
		Values          seqChoice
	}

	seqChoice struct {
		Octets []byte                `asn1:"optional"`
		Oid    asn1.ObjectIdentifier `asn1:"optional"`
		String string                `asn1:"optional"`
	}
)

// isHolder checks if the holder corresponds to the certificate
func (h *holder) isHolder(cert *x509.Certificate) bool {
	if h.BaseCertificateID.Serial != nil && h.BaseCertificateID.Serial.Cmp(cert.SerialNumber) == 0 {
		if h.BaseCertificateID.Serial.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}

	for _, e := range h.EntityName {
		if bytes.Compare(e.Bytes, cert.RawIssuer) == 0 {
			return true
		}
	}

	return false
}

// getAttribute returns the attribute stored with the given OID
func (aci *attributeCertificateInfo) getAttribute(oid asn1.ObjectIdentifier) (a *attribute) {
	for i, attr := range aci.Attributes {
		if attr.Type.Equal(oid) {
			a = &aci.Attributes[i]
			break
		}
	}
	return
}

// processVoExtension parses a general name from the raw value
func parseGeneralName(v asn1.RawValue) (string, error) {
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }

	switch v.Tag {
	case 1:
		fallthrough
	case 2:
		fallthrough
	case 6:
		return string(v.Bytes), nil
	// Name
	case 4:
		var nameSeq pkix.RDNSequence
		if _, err := asn1.Unmarshal(v.Bytes, &nameSeq); err != nil {
			return "", err
		}
		var name pkix.Name
		name.FillFromRDNSequence(&nameSeq)
		return NameRepr(name), nil
	// Unknown
	default:
		return "", fmt.Errorf("Unsupported GeneralName tag: %d", v.Tag)
	}
}

// parseAttCertIssuer parses the AttCertIssuer choice
func parseAttCertIssuer(v asn1.RawValue) (string, error) {
	// AttCertIssuer ::= CHOICE {
	//      v1Form      GeneralNames,  -- MUST NOT be used in this profile
	//	v2Form  [0] V2Form         -- v2 only
	// }
	// V2Form ::= SEQUENCE {
	//	issuerName             GeneralNames  OPTIONAL,
	//	baseCertificateID  [0] IssuerSerial  OPTIONAL,
	//	objectDigestInfo   [1] ObjectDigestInfo  OPTIONAL
	// }

	if v.Tag != 0 {
		return "", errors.New("Only V2Form supported for AttCertIssuer")
	}

	var v2form v2Form
	if _, err := asn1.Unmarshal(v.Bytes, &v2form); err != nil {
		return "", err
	}

	return parseGeneralName(v2form.IssuerName)
}

// parseVomsAttribute parsed the voms extension
func parseVomsAttribute(cert *x509.Certificate, ac *attributeCertificate) (vomsAttr *VomsAttribute, err error) {
	if rawAttr := ac.AcInfo.getAttribute(vomsAttrOid); rawAttr != nil {
		if !rawAttr.Value.IsCompound {
			return nil, errors.New("Expecting a compound attribute")
		}
		var attr ietfAttrSyntax
		if _, err = asn1.Unmarshal(rawAttr.Value.Bytes, &attr); err != nil {
			return
		}

		fqan := string(attr.Values.Octets)
		var vo string
		parts := strings.Split(fqan, "/")
		if len(parts) > 1 {
			vo = parts[1]
		}

		var paseq asn1.RawValue
		if _, err = asn1.Unmarshal(attr.PolicyAuthority.Bytes, &paseq); err != nil {
			return
		}

		var policyAuthority string
		if policyAuthority, err = parseGeneralName(paseq); err != nil {
			return
		}

		var issuer string
		if issuer, err = parseAttCertIssuer(ac.AcInfo.Issuer); err != nil {
			return
		}

		vomsAttr = &VomsAttribute{
			Subject:         NameRepr(cert.Subject),
			Issuer:          issuer,
			Vo:              vo,
			Fqan:            fqan,
			NotAfter:        ac.AcInfo.Validity.NotAfter,
			NotBefore:       ac.AcInfo.Validity.NotBefore,
			PolicyAuthority: policyAuthority,
		}
	}
	return
}

// parseVomsAttribute parses the VO extensions.
// It looks if there is a known certificate in the chain for which the extensions were issued,
// and process them.
func (proxy *X509Proxy) getVomsAttribute(ac *attributeCertificate) (vomsAttr *VomsAttribute, err error) {
	if ac.AcInfo.Holder.isHolder(proxy.Certificate) {
		return parseVomsAttribute(proxy.Certificate, ac)
	}
	for _, cert := range proxy.Chain {
		if ac.AcInfo.Holder.isHolder(cert) {
			return parseVomsAttribute(cert, ac)
		}
	}
	return
}

// parseVomsExtensions parses the Voms extensions
func (proxy *X509Proxy) parseVomsExtensions(raw []byte) (vomsAttrs []VomsAttribute, err error) {
	var acs [][]attributeCertificate
	if _, err = asn1.Unmarshal(raw, &acs); err != nil {
		return
	}

	for _, seq := range acs {
		for _, ac := range seq {
			var vomsAttr *VomsAttribute
			if vomsAttr, err = proxy.getVomsAttribute(&ac); err != nil {
				return
			} else if vomsAttr != nil {
				vomsAttrs = append(vomsAttrs, *vomsAttr)
			}
		}
	}

	return
}

// parseExtensions processes the proxy extensions
func (proxy *X509Proxy) parseExtensions(cert *x509.Certificate) (err error) {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(vomsExtOid) {
			var newAttrs []VomsAttribute
			newAttrs, err = proxy.parseVomsExtensions(extension.Value)
			if err != nil {
				return
			} else if newAttrs != nil {
				proxy.VomsAttributes = append(proxy.VomsAttributes, newAttrs...)
			}
		}
	}
	return
}
