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
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterDirective("kms_certificate", parseKMSCertificate)
}

// parseKMSCertificate parses the kms_certificate directive, which loads a
// certificate whose private key lives in a KMS:
//
//	kms_certificate <key-uri> {
//	    certificate       <path>
//	    pin               <pin>
//	    storage_directory <path>
//	    tags              <tags...>
//	}
//
// The tls directive has no extension point for third-party certificate
// loaders, which is why this is a directive of its own. It needs no entry in
// the directive order, because that list only orders directives producing HTTP
// handlers.
func parseKMSCertificate(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	var l Loader
	if err := l.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}

	// The value must be the slice itself, not a pointer to it. buildTLSApp
	// groups certificate loaders with reflection, keeping only values whose
	// kind is reflect.Slice, and discards anything else without an error.
	return []httpcaddyfile.ConfigValue{{
		Class: "tls.cert_loader",
		Value: l,
	}}, nil
}
