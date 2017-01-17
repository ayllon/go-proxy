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
		CurrentTime: time.Now(),
	}
}

func TestVerifyRFC(t *testing.T) {
	options := iniVerifyOptions(t)
	options.CurrentTime = time.Date(2016, 05, 18, 12, 37, 30, 0, gmt)

	p := loadProxy("test-samples/RfcProxy.pem", t)
	if e := p.Verify(options); e != nil {
		t.Error(e)
	}
}
