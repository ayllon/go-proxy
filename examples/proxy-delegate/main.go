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

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"gitlab.cern.ch/flutter/go-proxy"
	"log"
	"os"
	"time"
)

var proxyPath = flag.String("file", "", "Proxy location")
var strength = flag.Int("bits", 1024, "New proxy strength")
var lifetime = flag.Duration("lifetime", 1*time.Hour, "New proxy duration")

func getProxyPath() string {
	if path := os.Getenv("X509_USER_PROXY"); path != "" {
		return path
	}

	return fmt.Sprintf("/tmp/x509up_u%d", os.Getuid())
}

func main() {
	flag.Parse()

	if *proxyPath == "" {
		*proxyPath = getProxyPath()
	}
	if flag.NArg() != 1 {
		log.Fatal("Please, specify the output file")
	}
	if *proxyPath == flag.Arg(0) {
		log.Fatal("Input and output can not be the same")
	}

	var p proxy.X509Proxy
	if e := p.DecodeFromFile(*proxyPath); e != nil {
		log.Fatal(e)
	}

	var r proxy.X509ProxyRequest
	log.Printf("Generating request %d", *strength)
	if e := r.Init(*strength, x509.SHA256WithRSA); e != nil {
		log.Fatal(e)
	}

	log.Printf("Signing new proxy with a lifetime of %s", lifetime.String())
	new, e := p.SignRequest(&r, *lifetime)
	if e != nil {
		log.Fatal(e)
	}

	log.Print("Building full chain")
	new.PrivateKey = r.Key

	out, e := os.OpenFile(flag.Arg(0), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		log.Fatal(e)
	}
	defer out.Close()

	out.Write(new.Encode())
	log.Print("New proxy written into ", flag.Arg(0))
}
