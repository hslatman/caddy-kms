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

// Package fakekms provides an in-memory apiv1.KeyManager for tests, so that
// the rest of the module can be exercised without a TPM or any other
// hardware. It is internal and test-only.
package fakekms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"go.step.sm/crypto/kms/apiv1"
)

// KeyManager is an in-memory apiv1.KeyManager. It implements no certificate
// interfaces; embed it in CertManager or ChainManager for those.
type KeyManager struct {
	// Signer is returned by CreateSigner.
	Signer crypto.Signer

	// Chain is returned by the certificate interfaces, leaf first.
	Chain []*x509.Certificate

	// SignerErr, when non-nil, is returned by CreateSigner instead of Signer.
	SignerErr error

	// LoadErr, when non-nil, is returned by the certificate interfaces.
	LoadErr error

	// Signers, Loads and Closes count calls, for tests that assert on
	// caching and pooling behaviour.
	Signers atomic.Int64
	Loads   atomic.Int64
	Closes  atomic.Int64
}

// New returns a KeyManager holding a fresh ECDSA P-256 key and a self-signed
// server certificate valid for dnsNames.
func New(t testing.TB, dnsNames ...string) *KeyManager {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ecdsa key: %v", err)
	}
	return newKeyManager(t, key, dnsNames)
}

// NewRSA is like New, but generates a 2048-bit RSA key.
func NewRSA(t testing.TB, dnsNames ...string) *KeyManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	return newKeyManager(t, key, dnsNames)
}

func newKeyManager(t testing.TB, key crypto.Signer, dnsNames []string) *KeyManager {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "caddy-kms test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return &KeyManager{Signer: key, Chain: []*x509.Certificate{cert}}
}

// GetPublicKey implements apiv1.KeyManager.
func (k *KeyManager) GetPublicKey(*apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	return k.Signer.Public(), nil
}

// CreateKey implements apiv1.KeyManager. Key creation is out of scope.
func (k *KeyManager) CreateKey(*apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, apiv1.NotImplementedError{}
}

// CreateSigner implements apiv1.KeyManager.
func (k *KeyManager) CreateSigner(*apiv1.CreateSignerRequest) (crypto.Signer, error) {
	k.Signers.Add(1)
	if k.SignerErr != nil {
		return nil, k.SignerErr
	}
	return k.Signer, nil
}

// Close implements apiv1.KeyManager.
func (k *KeyManager) Close() error {
	k.Closes.Add(1)
	return nil
}

// CertManager adds apiv1.CertificateManager to a KeyManager, modelling a
// backend that can return a leaf but not a chain.
type CertManager struct {
	*KeyManager
}

// LoadCertificate implements apiv1.CertificateManager.
func (c *CertManager) LoadCertificate(*apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	c.Loads.Add(1)
	if c.LoadErr != nil {
		return nil, c.LoadErr
	}
	return c.Chain[0], nil
}

// StoreCertificate implements apiv1.CertificateManager. Storing is out of scope.
func (c *CertManager) StoreCertificate(*apiv1.StoreCertificateRequest) error {
	return apiv1.NotImplementedError{}
}

// ChainManager adds apiv1.CertificateChainManager to a CertManager, modelling
// a backend such as TPMKMS that stores a whole chain.
type ChainManager struct {
	*CertManager
}

// LoadCertificateChain implements apiv1.CertificateChainManager.
func (c *ChainManager) LoadCertificateChain(*apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	c.Loads.Add(1)
	if c.LoadErr != nil {
		return nil, c.LoadErr
	}
	return c.Chain, nil
}

// StoreCertificateChain implements apiv1.CertificateChainManager. Storing is
// out of scope.
func (c *ChainManager) StoreCertificateChain(*apiv1.StoreCertificateChainRequest) error {
	return apiv1.NotImplementedError{}
}

// RefusePSS wraps s so that RSA-PSS signing fails, modelling a TPM RSA key
// created with the RSASSA scheme. Such a key cannot serve TLS 1.3.
func RefusePSS(s crypto.Signer) crypto.Signer {
	return pssRefuser{s}
}

type pssRefuser struct {
	crypto.Signer
}

func (p pssRefuser) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("scheme is RSASSA; PSS not supported by this key")
	}
	return p.Signer.Sign(rnd, digest, opts)
}

// Interface guards
var (
	_ apiv1.KeyManager              = (*KeyManager)(nil)
	_ apiv1.CertificateManager      = (*CertManager)(nil)
	_ apiv1.CertificateChainManager = (*ChainManager)(nil)
)
