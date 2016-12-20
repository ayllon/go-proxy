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
	"io/ioutil"
	"path"
	"testing"
)

func TestParseMalformed(t *testing.T) {
	var p X509Proxy
	if e := p.Decode([]byte("RANDOM GARBAGE")); e == nil {
		t.Fatal("Expected an error")
	}
}

func commonAsserts(proxy *X509Proxy, t *testing.T) {
	if proxy == nil {
		t.Fatal("Proxy must not be nil")
	}
	if proxy.Raw == nil {
		t.Fatal("No certificate loaded")
	}
	if proxy.PrivateKey != nil {
		t.Fatal("Unexpected private key")
	}
	if NameRepr(proxy.Identity) != "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=saketag/CN=678984/CN=Alejandro Alvarez Ayllon" {
		t.Fatal("Unexpected user dn: ", proxy.Subject)
	}
	if len(proxy.VomsAttributes) != 1 {
		t.Fatal("Was expecting at least one VO extension")
	}
	if proxy.VomsAttributes[0].Vo != "dteam" {
		t.Fatal("Expecting dteam VO")
	}
	if proxy.VomsAttributes[0].PolicyAuthority != "dteam://voms2.hellasgrid.gr:15004" {
		t.Fatal("Unexpected PolicyAuthority")
	}
	if len(proxy.Chain) != 1 {
		t.Fatal("Expecting one certificate in the chain")
	}
	if proxy.DelegationID() == "" {
		t.Fatal("Delegation id empty")
	}
}

// loadChain reads into a buffer a list of pem files under test-samples
func loadChain(paths ...string) ([]byte, error) {
	var full []byte

	for _, file := range paths {
		var content []byte
		var err error

		fullPath := path.Join("test-samples", file)
		if content, err = ioutil.ReadFile(fullPath); err != nil {
			return nil, err
		}
		full = append(full, content...)
		full = append(full, '\n')
	}

	return full, nil
}

func TestLegacyProxy(t *testing.T) {
	full, err := loadChain("LegacyProxy.pem", "BaseCert.pem")
	if err != nil {
		t.Fatal(err)
	}

	var p X509Proxy
	if e := p.Decode(full); e != nil {
		t.Fatal(e)
	}

	commonAsserts(&p, t)
	if p.ProxyType != TypeLegacy {
		t.Fatal("Expecting Legacy proxy")
	}
}

func TestDraftProxy(t *testing.T) {
	full, err := loadChain("DraftProxy.pem", "BaseCert.pem")
	if err != nil {
		t.Fatal(err)
	}

	var p X509Proxy
	if e := p.Decode(full); e != nil {
		t.Fatal(e)
	}

	commonAsserts(&p, t)
	if p.ProxyType != TypeDraft {
		t.Fatal("Expecting Draft proxy")
	}
}

func TestRfcProxy(t *testing.T) {
	full, err := loadChain("RfcProxy.pem", "BaseCert.pem")
	if err != nil {
		t.Fatal(err)
	}

	var p X509Proxy
	if e := p.Decode(full); e != nil {
		t.Fatal(e)
	}

	commonAsserts(&p, t)
	if p.ProxyType != TypeRFC3820 {
		t.Fatal("Expecting RFC proxy")
	}
}

func TestSerialize(t *testing.T) {
	original, err := loadChain("RfcProxy.pem", "BaseCert.pem")
	if err != nil {
		t.Fatal(err)
	}

	var p X509Proxy
	if e := p.Decode(original); e != nil {
		t.Fatal(e)
	}

	// loadChain appends an extra \n!
	pem := p.Encode()
	if !bytes.Equal(original[:len(original)-1], pem) {
		t.Fatal("Serialized version does not match the original one")
	}
}
