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
	"errors"
	"fmt"
	"os"
)

var (
	ErrProxyNotFound = errors.New("User proxy not found")
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetCertAndKeyLocation returns the location of the user cert and key
// (or proxy)
func GetCertAndKeyLocation() (string, string, error) {
	// Try environment
	x509proxy := os.Getenv("X509_USER_PROXY")
	if x509proxy != "" {
		return x509proxy, x509proxy, nil
	}

	// Try default location
	x509proxy = fmt.Sprintf("/tmp/x509up_u%d", os.Getuid())
	if exists(x509proxy) {
		return x509proxy, x509proxy, nil
	}

	// Try user cert and key environment
	x509cert := os.Getenv("X509_USER_CERT")
	x509key := os.Getenv("X509_USER_KEY")
	if x509cert != "" || x509key != "" {
		return x509cert, x509key, nil
	}

	// Otherwise, try hostcert and hostkey
	x509cert = "/etc/grid-security/hostcert.pem"
	x509key = "/etc/grid-security/hostkey.pem"
	if exists(x509cert) || exists(x509key) {
		return x509cert, x509key, nil
	}

	// No idea!
	return "", "", ErrProxyNotFound
}
