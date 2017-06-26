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
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

var (
	dcNameOid = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	cnNameOid = asn1.ObjectIdentifier{2, 5, 4, 3}
	emailOid  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// NameRepr generates a string representation of the pkix.Name
func NameRepr(name *pkix.Name) string {
	components := make([]string, 0, 10)
	for _, name := range name.Names {
		t := name.Type
		value, ok := name.Value.(string)
		if !ok {
			continue
		}

		if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
			switch t[3] {
			case 3:
				components = append(components, fmt.Sprintf("CN=%s", value))
			case 6:
				components = append(components, fmt.Sprintf("C=%s", value))
			case 7:
				components = append(components, fmt.Sprintf("L=%s", value))
			case 8:
				components = append(components, fmt.Sprintf("ST=%s", value))
			case 9:
				components = append(components, fmt.Sprintf("STREET=%s", value))
			case 10:
				components = append(components, fmt.Sprintf("O=%s", value))
			case 11:
				components = append(components, fmt.Sprintf("OU=%s", value))
			}
		} else if t.Equal(dcNameOid) {
			components = append(components, fmt.Sprintf("DC=%s", value))
		} else if t.Equal(emailOid) {
			components = append(components, fmt.Sprintf("emailAddress=%s", value))
		}
	}
	return "/" + strings.Join(components, "/")
}

// KeyUsageRepr generates a string representing the key usage.
func KeyUsageRepr(k x509.KeyUsage) string {
	var usages []string

	if k&x509.KeyUsageDigitalSignature > 0 {
		usages = append(usages, "Digital Signature")
	}
	if k&x509.KeyUsageContentCommitment > 0 {
		usages = append(usages, "Content Commitment")
	}
	if k&x509.KeyUsageKeyEncipherment > 0 {
		usages = append(usages, "Key Encipherment")
	}
	if k&x509.KeyUsageDataEncipherment > 0 {
		usages = append(usages, "Data Encipherment")
	}
	if k&x509.KeyUsageKeyAgreement > 0 {
		usages = append(usages, "Key Agreement")
	}
	if k&x509.KeyUsageCertSign > 0 {
		usages = append(usages, "Cert Sign")
	}
	if k&x509.KeyUsageCRLSign > 0 {
		usages = append(usages, "CRL Sign")
	}
	if k&x509.KeyUsageEncipherOnly > 0 {
		usages = append(usages, "Encipher Only")
	}
	if k&x509.KeyUsageDecipherOnly > 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}
