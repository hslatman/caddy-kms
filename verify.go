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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// errKeyMismatch is returned when the KMS key does not belong to the
// certificate. In practice this means the certificate was rotated without the
// key, or the wrong key was named.
var errKeyMismatch = errors.New("public key in certificate does not match the KMS key")

// errNoPSS is returned when an RSA key cannot produce RSA-PSS signatures.
// TLS 1.3 requires PSS for RSA, and a TPM RSA key created with the RSASSA
// scheme cannot produce it.
var errNoPSS = errors.New("key cannot produce RSA-PSS signatures, which TLS 1.3 requires; " +
	"a TPM RSA key created with the RSASSA scheme cannot serve TLS 1.3, so recreate it as " +
	"ECDSA P-256 or with the RSAPSS scheme")

// verifyKeyPair checks that signer holds the private key belonging to leaf,
// and that it can produce the kind of signature TLS will ask it for. Both
// checks run at provision time so that a misconfiguration fails config load
// instead of every handshake.
func verifyKeyPair(leaf *x509.Certificate, signer crypto.Signer) error {
	pub, ok := leaf.PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		return fmt.Errorf("unsupported certificate public key type %T", leaf.PublicKey)
	}
	if !pub.Equal(signer.Public()) {
		return errKeyMismatch
	}
	return testSign(signer)
}

// testSign asks signer for one signature and verifies it. For RSA it insists
// on PSS, because that is what TLS 1.3 uses.
func testSign(signer crypto.Signer) error {
	msg := []byte("caddy-kms key verification")
	sum := sha256.Sum256(msg)

	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		sig, err := signer.Sign(rand.Reader, sum[:], opts)
		if err != nil {
			return fmt.Errorf("%w: %w", errNoPSS, err)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, sum[:], sig, opts); err != nil {
			return fmt.Errorf("%w: %w", errNoPSS, err)
		}
	case *ecdsa.PublicKey:
		sig, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("test signature failed: %w", err)
		}
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return errors.New("test signature did not verify against the certificate public key")
		}
	case ed25519.PublicKey:
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("test signature failed: %w", err)
		}
		if !ed25519.Verify(pub, msg, sig) {
			return errors.New("test signature did not verify against the certificate public key")
		}
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
	return nil
}
