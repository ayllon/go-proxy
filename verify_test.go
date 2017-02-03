/*
 * Copyright (c) CERN 2017
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
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"io/ioutil"
	"testing"
	"time"
)

var vomsPath = flag.String("vomspath", "test-samples/vomsdir", "VOMS directory")
var caPath = flag.String("capath", "test-samples/ca", "CA Path")
var gmt *time.Location

func init() {
	var err error
	if gmt, err = time.LoadLocation("GMT"); err != nil {
		panic(err)
	}
}

func iniVerifyOptions(t *testing.T) VerifyOptions {
	roots, err := LoadCAPath(*caPath, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, derSubject := range roots.Subjects() {
		var subjectSeq pkix.RDNSequence
		if _, err := asn1.Unmarshal(derSubject, &subjectSeq); err != nil {
			t.Fatal(err)
		}
		var subject pkix.Name
		subject.FillFromRDNSequence(&subjectSeq)
		t.Log("CA ", NameRepr(&subject))
	}

	return VerifyOptions{
		Roots:       roots,
		VomsDir:     *vomsPath,
		CurrentTime: time.Date(2016, 05, 18, 12, 37, 30, 0, gmt),
	}
}

// Verify a normal valid RFC proxy
func TestVerifyRFC(t *testing.T) {
	options := iniVerifyOptions(t)

	p := loadProxy("test-samples/RfcProxy.pem", t)
	if e := p.Verify(options); e != nil {
		t.Error(e)
	}
}

// Verify an entity certificate (no proxy!)
func TestVerifyEC(t *testing.T) {
	options := iniVerifyOptions(t)

	p := loadProxy("test-samples/EC.pem", t)
	if e := p.Verify(options); e != nil {
		t.Error(e)
	}
}

// Verify a valid RFC proxy, but expired
func TestVerifyExpired(t *testing.T) {
	options := iniVerifyOptions(t)
	options.CurrentTime = time.Date(2020, 01, 01, 01, 01, 01, 0, gmt)

	p := loadProxy("test-samples/RfcProxy.pem", t)
	if e := p.Verify(options); e == nil {
		t.Error("Verification must fail")
	} else {
		t.Log(e)
	}
}

// Load an RFC proxy with an incomplete chain
func TestIncomplete(t *testing.T) {
	content, e := ioutil.ReadFile("test-samples/BadIncomplete.pem")
	if e != nil {
		t.Fatal(e)
	}
	p := &X509Proxy{}
	if e = p.Decode(content); e == nil {
		t.Error("Loading must fail")
	}
}

// Verify an RFC proxy, not having installed the ROOT CA, *but* the proxy contains the full chain
// Must fail
func TestVerifyBadCA(t *testing.T) {
	var e error
	options := iniVerifyOptions(t)
	// We know we have no root ca here
	options.Roots, e = LoadCAPath("test-samples/vomsdir", false)
	if e != nil {
		t.Fatal(e)
	}

	p := loadProxy("test-samples/BadFull.pem", t)
	if e := p.Verify(options); e == nil {
		t.Error("Verification must fail")
	} else {
		t.Log(e)
	}
}

// Verify a proxy generated from a proxy
func TestVerifyNested(t *testing.T) {
	options := iniVerifyOptions(t)
	options.CurrentTime = time.Date(2017, 02, 03, 10, 15, 00, 0, gmt)

	p := loadProxy("test-samples/NestedProxy.pem", t)
	if e := p.Verify(options); e != nil {
		t.Error(e)
	}
}

// Verify a forged proxy. The issuer is valid, but the subject has been tampered
func TestVerifyForged(t *testing.T) {
	options := iniVerifyOptions(t)
	options.CurrentTime = time.Date(2017, 02, 03, 11, 00, 00, 0, gmt)

	p := loadProxy("test-samples/BadForgedProxy.pem", t)
	if e := p.Verify(options); e == nil {
		t.Error("Must have failed")
	} else {
		t.Log(e)
	}
}
