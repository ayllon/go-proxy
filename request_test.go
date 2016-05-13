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
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

var SigningCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIMIzCCCwugAwIBAgIFAJIwp7EwDQYJKoZIhvcNAQENBQAwgZgxEjAQBgoJkiaJ
k/IsZAEZFgJjaDEUMBIGCgmSJomT8ixkARkWBGNlcm4xFjAUBgNVBAsTDU9yZ2Fu
aWMgVW5pdHMxDjAMBgNVBAsTBVVzZXJzMRAwDgYDVQQDEwdzYWtldGFnMQ8wDQYD
VQQDEwY2Nzg5ODQxITAfBgNVBAMTGEFsZWphbmRybyBBbHZhcmV6IEF5bGxvbjAe
Fw0xNjA1MTgxMjMyMTNaFw0xNjA1MTgxMjM4MTNaMIGtMRIwEAYKCZImiZPyLGQB
GRYCY2gxFDASBgoJkiaJk/IsZAEZFgRjZXJuMRYwFAYDVQQLEw1PcmdhbmljIFVu
aXRzMQ4wDAYDVQQLEwVVc2VyczEQMA4GA1UEAxMHc2FrZXRhZzEPMA0GA1UEAxMG
Njc4OTg0MSEwHwYDVQQDExhBbGVqYW5kcm8gQWx2YXJleiBBeWxsb24xEzARBgNV
BAMTCjI0NTI2NjIxOTMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALzJ/aCx
gmGR0u6lCT0UAh02b/ucgiYz/rKsdDvWkayrgVmltg1BdulgkBu3NLxWm7VrlqeF
Q4iCrzt3pViWV8a14cnDYHHbgwlXi2mVNKSIcTAmMuCsHEwG3CbaoNbjnpfLTIIt
eMYmUyS0ghwQAhhmMmPzrgrbtCjVldwwfBa7AgMBAAGjggjfMIII2zCCCHkGCisG
AQQBvkVkZAUEgghpMIIIZTCCCGEwgghdMIIHRQIBATCBsKCBrTCBnqSBmzCBmDES
MBAGCgmSJomT8ixkARkWAmNoMRQwEgYKCZImiZPyLGQBGRYEY2VybjEWMBQGA1UE
CxMNT3JnYW5pYyBVbml0czEOMAwGA1UECxMFVXNlcnMxEDAOBgNVBAMTB3Nha2V0
YWcxDzANBgNVBAMTBjY3ODk4NDEhMB8GA1UEAxMYQWxlamFuZHJvIEFsdmFyZXog
QXlsbG9uAgplEAWrAAAAAUYioF4wXKRaMFgxCzAJBgNVBAYTAkdSMRMwEQYDVQQK
DApIZWxsYXNHcmlkMRYwFAYDVQQLDA1oZWxsYXNncmlkLmdyMRwwGgYDVQQDDBN2
b21zMi5oZWxsYXNncmlkLmdyMA0GCSqGSIb3DQEBCwUAAhEA27cjN2EkSOKM5cBU
BjxG5zAiGA8yMDE2MDUxODEyMzcxM1oYDzIwMTYwNTE4MTIzODEzWjCBgzCBgAYK
KwYBBAG+RWRkBDFyMHCgI4YhZHRlYW06Ly92b21zMi5oZWxsYXNncmlkLmdyOjE1
MDA0MEkEIC9kdGVhbS9Sb2xlPU5VTEwvQ2FwYWJpbGl0eT1OVUxMBCUvZHRlYW0v
Y2Vybi9Sb2xlPU5VTEwvQ2FwYWJpbGl0eT1OVUxMMIIFXzCCBS8GCisGAQQBvkVk
ZAoEggUfMIIFGzCCBRcwggUTMIID+6ADAgECAgIRyzANBgkqhkiG9w0BAQsFADBj
MQswCQYDVQQGEwJHUjETMBEGA1UEChMKSGVsbGFzR3JpZDEiMCAGA1UECxMZQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdGllczEbMBkGA1UEAxMSSGVsbGFzR3JpZCBDQSAy
MDA2MB4XDTE2MDQwNDE0Mjc1MVoXDTE2MDcxMDE0Mjc1MVowWDELMAkGA1UEBhMC
R1IxEzARBgNVBAoMCkhlbGxhc0dyaWQxFjAUBgNVBAsMDWhlbGxhc2dyaWQuZ3Ix
HDAaBgNVBAMME3ZvbXMyLmhlbGxhc2dyaWQuZ3IwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC30Mcv4txDE1BBq99E/T4JFQdJLH5A2lnA0WY+uf3N67+K
wyTdRmS9Q+PMew0/k5+lDGcH+RruX8ile7U2BNS/2Z5dWWwyuW+sUoxnlqERN6jH
TADqSINWHYlxfp6NpTy4XoKnaVV3tw0dtVRg5/iUv1pDDg+A2flcm71AejHDnNCE
OS94C43505k57VuL7UXU4tgaKQHnUQW6rO4ykT8Yw47Nm6R5IRC0Asj8Nbk3xZOy
vL5F/g2bntLAeE0B19UOOvYaFSy3o1iBajht1PtNlTkfXYTjP5fGNF/XlKhy3HGa
N+dRX+GRiW9Sw5MLAeHNyGIr9zBk/pcH71T0higBAgMBAAGjggHaMIIB1jAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIEsDAdBgNVHQ4EFgQU9DPPa81siqapiQ+c
q4gL7VVKizIwgZIGA1UdIwSBijCBh4AUCdfyXQvjOh9s5EO+AT1PPLBmXiahbKRq
MGgxCzAJBgNVBAYTAkdSMRMwEQYDVQQKEwpIZWxsYXNHcmlkMSIwIAYDVQQLExlD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMSAwHgYDVQQDExdIZWxsYXNHcmlkIFJv
b3QgQ0EgMjAwNoIBATAlBgNVHRIEHjAcgRpoZWxsYXNncmlkLWNhQGdyaWQuYXV0
aC5ncjAeBgNVHREEFzAVghN2b21zMi5oZWxsYXNncmlkLmdyMHEGA1UdIARqMGgw
ZgYNKwYBBAGBgQMUAQECAzBVMFMGCCsGAQUFBwIBFkdodHRwOi8vY3JsLmdyaWQu
YXV0aC5nci9oZWxsYXNncmlkLWNhLTIwMDYvY3BzL0hlbGxhc0dyaWQtQ0EtQ1At
Q1BTLnBkZjBIBgNVHR8EQTA/MD2gO6A5hjdodHRwOi8vY3JsLmdyaWQuYXV0aC5n
ci9oZWxsYXNncmlkLWNhLTIwMDYvODJiMzZmY2EuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQBEKDJi/LDjOQATq2jJ17kUdco4bieybWiwShk/d9pNKUjYE7Y6prFjXFlS
HrzxET1Q12hvpEaHeUCyUjx2BGRATMDoKw2iwZIMq8Xy38kwDQ4D8HIXZrDPzq4o
Sh8aC2XkAK1keuC0tBK+l+iVDtUGUpyeeiGFSZQDvtqiMS0OsnHQWoYaXt8Y2u58
RMY++9iVGkwQxr0zhJ0Oc+LZ6RjP2DoHE8ViQx1bQNg1Jz9wtaA/a2lW3yt5cd/7
eJi00jtuwbJwmrXv68o69vx9IqJuCYapuG7Yp1EUuFYkk41rx3h1a5nZRnxr4sIX
9MrwRSIbyX8cK9M00/6qcMXizqBUMAkGA1UdOAQCBQAwHwYDVR0jBBgwFoAU9DPP
a81siqapiQ+cq4gL7VVKizIwDQYJKoZIhvcNAQELBQADggEBAJMg0rjV9AXdh6ez
EGL5f/hlEUq6d+uTmLnb3JKlTJCIbA/AO31DhdswlbnuyJp44fRoxcXJUanAK91N
7AnAH/58biuAIyqD5vmUx5wDkImw6SSEFCb9T280tUMRLwc++Hk3zudSmyY+Q0t6
lvHgQMjaAQpfk/2qnEDnT1bSsxCSiE3zxi2pmpWUksjO554BEY471sLnCXlPHkeP
KE+SyKiunR05j1oIE9ty8TwtlhsQnQC3Pw3VGMTlZnEXvOcVTO6HjlT0wlAJlTs7
tb5jdLBfb6rncSzGhpX/4plquKwgQVMhyiB3sk/mzNa7/+J9+7NR8i/TWKqFBPwk
Qa8lERIwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
9oyNbySnYq5ACWD2s/Jj2BiiV+gwHQYIKwYBBQUHAQ4BAf8EDjAMMAoGCCsGAQUF
BxUBMA0GCSqGSIb3DQEBDQUAA4IBAQA+3kuP3RJ3VSPd1UH9HhMzVJCHt3SYMtI0
iBHYszSWC6ppzrhYs4FRNKM+NNTm9O5NTjdf4gB/M5S4raIMkakFN4OOdX5GHh6K
kGIHICDOrHcZgUsQT4MDEIJIcKHM1zx9pOX1mqMUZ1GhuNFtcXy5Ob5TL4tqMSnJ
3/+pIOq40v8p+vaHZZ5Ha4XFDHG/JkfrU34pbO5IFC4GJIB+xop+HEJ3XMKigaSq
siOs0ZBPFReRIrox9/NGtL1Xffns4zakJiaglxW8BOEIiJcb/yvZbvV2vFbzrOH8
lR/i0zjHVmx+zcLAA4Q9+NOLVH/Ba7527a5OM64mpPk/nSBw9khW
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8yf2gsYJhkdLupQk9FAIdNm/7nIImM/6yrHQ71pGsq4FZpbYN
QXbpYJAbtzS8Vpu1a5anhUOIgq87d6VYllfGteHJw2Bx24MJV4tplTSkiHEwJjLg
rBxMBtwm2qDW456Xy0yCLXjGJlMktIIcEAIYZjJj864K27Qo1ZXcMHwWuwIDAQAB
AoGAN2UVlLdBSJvfRsMKSO+8BxJYHX44+ji7fXX4zS4SpJXWaJWlK5KP776zyk4h
nTnUipE9LX5+6GlgPZTH4YyLyHNqXp1KSvEuiQsPmINQMnCOuIdbatIzI+QFPvQK
na4plhO3cFUs57iVOFLuCjwVTFh9DUrlah65Q62A+N3zx1ECQQDs33DcVLfNNok4
Q6t0mUdouE4Wd7thUwPrBOT4mmOQgpEuWF4VlK2+r+bZIBo/6Uzu3PcVJwp6UM57
APZ4z/51AkEAzAiTv5odUjMfsQtBlv/FKiTOfbF6eIdUhvcI41y4Kqz/AfLxNGPU
mPzt7TCulM8eFikEf+tI2h1FOtzOg8V6bwJBAM9Z1Tj6bB8Wo03+ZqNd3hW8aJbg
XsYWXnKnySwaMhf5Q893CX0ItoMbBhCBOplBx9e81AnPMCvcerNQJ3GgWVUCQB07
xV+Yh0b1yD6nrDgkYW2OZH+h5DhMu5Gy53UcHc8PhmITGvg0rYtWAgkQBpOPsXHf
YqOpZIDL3NV4OaarrsUCQCXyg2kuQQGBye9Uu61YhE1ipxR1mzh5+BE0hclLkw6e
5m3S9uXyvpPka8O+g6xMoiVuMB5+sNFbMKjLwfEAPAM=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIIuDCCBqCgAwIBAgIKZRAFqwAAAAFGIjANBgkqhkiG9w0BAQ0FADBWMRIwEAYK
CZImiZPyLGQBGRYCY2gxFDASBgoJkiaJk/IsZAEZFgRjZXJuMSowKAYDVQQDEyFD
RVJOIEdyaWQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTUwNjE2MDYxMzIw
WhcNMTYwNjE1MDYxMzIwWjCBmDESMBAGCgmSJomT8ixkARkWAmNoMRQwEgYKCZIm
iZPyLGQBGRYEY2VybjEWMBQGA1UECxMNT3JnYW5pYyBVbml0czEOMAwGA1UECxMF
VXNlcnMxEDAOBgNVBAMTB3Nha2V0YWcxDzANBgNVBAMTBjY3ODk4NDEhMB8GA1UE
AxMYQWxlamFuZHJvIEFsdmFyZXogQXlsbG9uMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAstHciTg2adwAoUOrhr/XR9O/uZSUnX8VhMn3u8WZlUVp+NhB
PKAvfmBcbIsm+LZOHKtiqpc6K9cj4i0XdRYq9mQObQrwth7E7viUlzWXMzYzHiTD
FfFskvNqh6N/K68GPK7TA5yCKLPs3cjAJ0sbszamDGlzN0HdMppVvARDWwAId2Eb
VdHsgyhrygCBb++VZMFkFk7aWnaOoeV6yDboV8MePN2ZpYyooDxLG//ru8k9ioZq
5TYsSHYKRFL9lqGOjx/3Oxmg5uHe7GtK8/Pq7lU+bbOclmSQoz+hA3tYfaUiLho0
QUS6b/7te/p79DI0tp9HQ0aseRowJKXv8IuR+QIDAQABo4IEQzCCBD8wHQYDVR0O
BBYEFPaMjW8kp2KuQAlg9rPyY9gYolfoMB8GA1UdIwQYMBaAFKWg/WZY/bndeuGy
nZ+j0eVQGJTnMIIBOAYDVR0fBIIBLzCCASswggEnoIIBI6CCAR+GTmh0dHA6Ly9j
YWZpbGVzLmNlcm4uY2gvY2FmaWxlcy9jcmwvQ0VSTiUyMEdyaWQlMjBDZXJ0aWZp
Y2F0aW9uJTIwQXV0aG9yaXR5LmNybIaBzGxkYXA6Ly8vQ049Q0VSTiUyMEdyaWQl
MjBDZXJ0aWZpY2F0aW9uJTIwQXV0aG9yaXR5LENOPUNFUk5QS0kwNSxDTj1DRFAs
Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln
dXJhdGlvbixEQz1jZXJuLERDPWNoP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/
YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCCAWIGCCsGAQUF
BwEBBIIBVDCCAVAwYwYIKwYBBQUHMAKGV2h0dHA6Ly9jYWZpbGVzLmNlcm4uY2gv
Y2FmaWxlcy9jZXJ0aWZpY2F0ZXMvQ0VSTiUyMEdyaWQlMjBDZXJ0aWZpY2F0aW9u
JTIwQXV0aG9yaXR5LmNydDCBwgYIKwYBBQUHMAKGgbVsZGFwOi8vL0NOPUNFUk4l
MjBHcmlkJTIwQ2VydGlmaWNhdGlvbiUyMEF1dGhvcml0eSxDTj1BSUEsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1jZXJuLERDPWNoP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1j
ZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5j
ZXJuLmNoL29jc3AwDgYDVR0PAQH/BAQDAgWgMD0GCSsGAQQBgjcVBwQwMC4GJisG
AQQBgjcVCIO90AmC7Y0Nhu2LK4He9TeFgNBiHoWK40yBtaoEAgFkAgEPMCkGA1Ud
JQQiMCAGCisGAQQBgjcKAwQGCCsGAQUFBwMEBggrBgEFBQcDAjAnBgNVHSAEIDAe
MA4GDCsGAQQBYAoEAgICADAMBgoqhkiG90wFAgIBMDUGCSsGAQQBgjcVCgQoMCYw
DAYKKwYBBAGCNwoDBDAKBggrBgEFBQcDBDAKBggrBgEFBQcDAjA7BgNVHREENDAy
oB8GCisGAQQBgjcUAgOgEQwPc2FrZXRhZ0BjZXJuLmNogQ9zYWtldGFnQGNlcm4u
Y2gwRAYJKoZIhvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQC
AgCAMAcGBSsOAwIHMAoGCCqGSIb3DQMHMA0GCSqGSIb3DQEBDQUAA4ICAQArhjyr
pIK2G/xclXpH04rjJd9Y99ZhctCk4AzdUyhtLrB7YcjSevcJMK3ThdNYFQ/LiPUO
1Cd1MQb+LJW9xHnNKoN2AIfP/rlARq9+GGWpTihPbKvCdcM95FXSLeMn48QTDFeB
A11Y55KIRGKCEddSuR0xd1VDPahXn67hIzpSiPFrklAa2WfXRe49a834eryNoZS0
Ab3IzXSCdXdjb21UdZut/E54iIDBLuOLZIPJSBq/rm1HXOyQ/U/jyzC/89EOCv8f
IOssOyWg72vMZ053t9sB/xT1wsQaHrE8V6Gcwj9ghz+HyBbPROmDYaNAV/sGeb8e
QcfWwBuecbkCNNCIMPUjtrE38xSTAz57KLMyxtfPSoUtMpL0/40TbpvqgCfWyB6d
XCN8YjghDOMWaBFjW+9lQKtiE3omxQFOH8cDwXZ5ve3YhIxSPTRqOqI/OnWzcEXb
LvLljd03tJs1xVIQ5WfQII4YEKvZqhVIMlyBr3EIuELZwfQeWe7jCwQ0AU2aAUur
NZBBgm3yesob3bl0EkDNiLVz4R9CxgRDVsvsswrDgOFAjwXIf4TQKci8iSZ1SDiF
TWIYDS6+IVhIBSwfA36oACK0DNoVWPs/r6pmCyYFORuI3Azs78w7FKXiPiEPRuRE
dWufPziFxnIH/iDDSx1reW6z3jmFUq1Y8YFCNQ==
-----END CERTIFICATE-----
`)

// Test the creation of a proxy request.
func TestCreateProxyRequest(t *testing.T) {
	var r X509ProxyRequest

	if err := r.Init(2048, x509.SHA256WithRSA); err != nil {
		t.Fatal(err)
	}
	if r.Key.N.BitLen() != 2048 {
		t.Fatal("Wrong bit size")
	}
	if r.Request.PublicKey.(*rsa.PublicKey).N.Cmp(r.Key.N) != 0 {
		t.Fatal("Request and private key do not match")
	}
}

// Test the creation of a new proxy.
func TestNewProxy(t *testing.T) {
	var r X509ProxyRequest
	var p X509Proxy

	if err := r.Init(2048, x509.SHA256WithRSA); err != nil {
		t.Fatal(err)
	}

	if err := p.Decode(SigningCert); err != nil {
		t.Fatal(err)
	}

	nested, err := p.SignRequest(&r, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if nested == nil {
		t.Fatal("New proxy is nil")
	}
	if nested.Key != nil {
		t.Fatal("The private key must not be set")
	}

	if nested.Certificate.PublicKey.(*rsa.PublicKey).N.Cmp(r.Key.N) != 0 ||
		nested.Certificate.PublicKey.(*rsa.PublicKey).E != r.Key.E {
		t.Fatal("New proxy public key does not match the private key used to sign the request")
	}

	if bytes.Compare(nested.Certificate.RawIssuer, p.Certificate.RawSubject) != 0 {
		t.Fatal("The issuer of the new proxy is not the original proxy")
	}

	if nested.Certificate.NotAfter.Sub(p.Certificate.NotAfter) > 0 {
		t.Fatal("The new proxy can not expire after the signing proxy")
	}
	if nested.Certificate.NotBefore.Sub(p.Certificate.NotBefore) < 0 {
		t.Fatal("The new proxy can not start before the signing proxy")
	}
	if nested.Subject == p.Subject {
		t.Fatal("The proxy can not have the same subject as the signing proxy")
	}
	if !strings.Contains(nested.Subject, p.Subject+"/CN=") {
		t.Fatalf("The proxy subject does not extend the signing proxy subject:\n\t%s\n\t%s\n",
			nested.Subject, p.Subject)
	}
	if bytes.Compare(nested.Chain[0].RawSubject, p.Certificate.RawSubject) != 0 {
		t.Fatal("The first certificate in the chain must be the signing certificate")
	}
}
