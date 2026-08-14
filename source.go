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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.uber.org/zap"
)

// errNoCertificateSource is returned when neither a certificate file is
// configured nor the backend can return one.
var errNoCertificateSource = errors.New(`the kms cannot load certificates, ` +
	`so "certificate" must be set to a PEM file path`)

// Source turns one Entry into a tls.Certificate whose private key stays in the
// KMS. It is the only type in this package that talks to go.step.sm/crypto.
//
// The lifecycle is newSource, Open, Resolve any number of times, Close.
type Source struct {
	entry Entry
	opts  apiv1.Options
	pool  *pool
	log   *zap.Logger

	// ctx is the context Open was given. Resolve reuses it because
	// caddytls.CertificateLoader takes no context, and because tying a KMS
	// read to a single handshake's context would let one client cancel a read
	// that other handshakes are waiting on.
	ctx context.Context
	km  apiv1.KeyManager
}

// newSource validates e and prepares a Source for it. It performs no I/O, so
// configuration errors surface before anything touches the KMS.
func newSource(e Entry, p *pool, log *zap.Logger) (*Source, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	opts, err := e.options()
	if err != nil {
		return nil, err
	}
	return &Source{entry: e, opts: opts, pool: p, log: log}, nil
}

// Open acquires the shared KeyManager. Every successful Open must be paired
// with exactly one Close.
func (s *Source) Open(ctx context.Context) error {
	km, err := s.pool.acquire(ctx, s.opts)
	if err != nil {
		return err
	}
	s.ctx, s.km = ctx, km

	// The TPM KMS defaults its storage directory relative to the working
	// directory, which is rarely where an external tool put the key. Log
	// whatever is in effect so that "key not found" is diagnosable.
	s.log.Info("opened kms",
		zap.String("type", string(s.opts.Type)),
		zap.String("key", s.entry.Key),
		zap.String("storage_directory", s.opts.StorageDirectory))
	return nil
}

// Close releases the shared KeyManager.
func (s *Source) Close() error {
	if s.km == nil {
		return nil
	}
	s.km = nil
	return s.pool.release(s.opts)
}

// Resolve builds a tls.Certificate for the entry. The returned certificate's
// PrivateKey is a crypto.Signer backed by the KMS; the key material is never
// extracted.
func (s *Source) Resolve() (*tls.Certificate, error) {
	if s.km == nil {
		return nil, errors.New("source is not open")
	}

	signer, err := s.km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: s.entry.Key})
	if err != nil {
		return nil, fmt.Errorf("creating signer for key %q: %w", s.entry.Key, err)
	}

	chain, err := s.chain()
	if err != nil {
		return nil, err
	}

	if err := verifyKeyPair(chain[0], signer); err != nil {
		return nil, fmt.Errorf("key %q: %w", s.entry.Key, err)
	}
	s.warn(chain)

	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}
	return &tls.Certificate{
		Certificate: der,
		PrivateKey:  signer,
		// Leaf must be set: certificate selection and client-support checks
		// read it, and leaving it nil would make Caddy re-parse on every
		// handshake.
		Leaf: chain[0],
	}, nil
}

// chain returns the certificate chain, leaf first, from whichever source the
// entry configures.
func (s *Source) chain() ([]*x509.Certificate, error) {
	if s.entry.Certificate != "" {
		return chainFromFile(s.entry.Certificate)
	}

	// Prefer the chain interface: a backend implementing both, as the TPM KMS
	// does, can return intermediates too.
	if ccm, ok := s.km.(apiv1.CertificateChainManager); ok {
		chain, err := ccm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{Name: s.entry.Key})
		if err != nil {
			return nil, fmt.Errorf("loading certificate chain for key %q: %w", s.entry.Key, err)
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("kms returned an empty certificate chain for key %q", s.entry.Key)
		}
		return chain, nil
	}
	if cm, ok := s.km.(apiv1.CertificateManager); ok {
		leaf, err := cm.LoadCertificate(&apiv1.LoadCertificateRequest{Name: s.entry.Key})
		if err != nil {
			return nil, fmt.Errorf("loading certificate for key %q: %w", s.entry.Key, err)
		}
		return []*x509.Certificate{leaf}, nil
	}
	return nil, fmt.Errorf("kms %q: %w", s.opts.Type, errNoCertificateSource)
}

// warn logs conditions that are suspicious but not worth refusing to start
// for. Failing here would block an operator who is mid-recovery.
func (s *Source) warn(chain []*x509.Certificate) {
	if time.Now().After(chain[0].NotAfter) {
		s.log.Warn("certificate has expired",
			zap.String("key", s.entry.Key),
			zap.Time("not_after", chain[0].NotAfter))
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			s.log.Warn("certificate chain is not in issuer order, which some clients reject",
				zap.String("key", s.entry.Key),
				zap.Int("position", i))
			break
		}
	}
}

// chainFromFile reads a PEM file and returns every certificate in it, in the
// order they appear. The first is taken to be the leaf.
func chainFromFile(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate %q: %w", path, err)
	}

	var chain []*x509.Certificate
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate in %q: %w", path, err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found in %q", path)
	}
	return chain, nil
}
