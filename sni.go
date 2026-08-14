// Copyright 2026 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddykms

import (
	"crypto/x509"
	"net"
	"strings"
)

// matchesSNI reports whether leaf can serve the name a client asked for. A
// client that sends no SNI matches, so that such clients still get the
// certificate.
//
// The certificate manager needs this because certmagic requires a manager to
// decline handshakes it has no certificate for, rather than erroring, so that
// other managers and issuers still get a chance.
func matchesSNI(leaf *x509.Certificate, serverName string) bool {
	if serverName == "" {
		return true
	}
	name := strings.ToLower(strings.TrimSuffix(serverName, "."))

	if ip := net.ParseIP(name); ip != nil {
		for _, candidate := range leaf.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}

	for _, san := range leaf.DNSNames {
		if matchesDNSName(strings.ToLower(san), name) {
			return true
		}
	}
	return false
}

// matchesDNSName reports whether name matches san, honouring a single leading
// wildcard label. A wildcard matches exactly one label, so *.example.com
// covers a.example.com but neither example.com nor a.b.example.com.
func matchesDNSName(san, name string) bool {
	if san == name {
		return true
	}
	if !strings.HasPrefix(san, "*.") {
		return false
	}
	suffix := san[1:] // ".example.com"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(name, suffix)
	return label != "" && !strings.Contains(label, ".")
}
