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

// Package caddykms serves TLS certificates whose private keys live in a key
// management system, using the KMS abstraction from go.step.sm/crypto.
//
// The private key and certificate are managed outside Caddy. Loading a
// certificate through this package suppresses Caddy's automatic certificate
// management for the names it covers, so no ACME issuance is attempted.
package caddykms

import (
	// Registering a backend here is all it takes to support it. Only pure-Go
	// backends are registered, so the default build needs no cgo.
	_ "go.step.sm/crypto/kms/softkms"
	_ "go.step.sm/crypto/kms/tpmkms"
)
