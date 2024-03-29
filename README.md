go-proxy
========

go-proxy is an utility library written in Go to handle X509 proxies, with and without VOMS extensions. It supports Legacy, Draft and RFC3820 proxies.

## What does it do
* X509 proxy parsing with and without VOMS exceptions.
* Re-delegating from an existing proxy.

## What doesn't it do
* It can't acquire VOMS extensions from a VOMS server.
* It can't create a brand new proxy from a user certificate and key. API limitation, mostly.

 [![GoDoc](https://godoc.org/github.com/ayllon/go-proxy?status.svg)](https://godoc.org/github.com/ayllon/go-proxy)
 
 
## Examples

### Load a proxy, print its VOMS
```go
package main

import (
	"flag"
	"github.com/ayllon/go-proxy"
	"log"
)

func main() {
	flag.Parse()

	var p proxy.X509Proxy
	if e := p.DecodeFromFile(flag.Arg(0)); e != nil {
		log.Fatal(e)
	}
	log.Print(p.Subject)
	for _, v := range p.VomsAttributes {
		log.Print(v.Vo)
		log.Print(v.Fqan)
	}
}
```
