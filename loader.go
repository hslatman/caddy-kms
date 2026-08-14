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
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(Loader{})
}

// Loader loads certificates whose private keys live in a KMS.
//
// Each certificate is resolved once, when the config is loaded, and cached by
// Caddy as an unmanaged certificate. Caddy skips automatic certificate
// management for any name it already holds a certificate for, so no ACME
// issuance is attempted and no extra configuration is needed to prevent it. A
// certificate rotated outside Caddy is picked up on the next reload; use
// tls.get_certificate.kms instead to pick one up without reloading.
//
// Loader must remain a slice type: the Caddyfile adapter groups certificate
// loaders using reflection and silently discards any loader whose kind is not
// a slice.
type Loader []Entry

// CaddyModule returns the Caddy module information.
func (Loader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_kms",
		New: func() caddy.Module { return new(Loader) },
	}
}

// Provision opens the KMS for every entry and validates its configuration, so
// that problems abort the config load rather than surfacing per handshake.
func (l *Loader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	log := ctx.Logger()

	for i := range *l {
		entry := (*l)[i].replace(repl)
		src, err := newSource(entry, defaultPool, log)
		if err != nil {
			return fmt.Errorf("certificate %d: %w", i, err)
		}
		if err := src.Open(ctx); err != nil {
			return fmt.Errorf("certificate %d: %w", i, err)
		}
		entry.src = src
		(*l)[i] = entry
	}
	return nil
}

// LoadCertificates implements caddytls.CertificateLoader.
func (l Loader) LoadCertificates() ([]caddytls.Certificate, error) {
	certs := make([]caddytls.Certificate, 0, len(l))
	for i, entry := range l {
		if entry.src == nil {
			return nil, fmt.Errorf("certificate %d: loader was not provisioned", i)
		}
		cert, err := entry.src.Resolve()
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		certs = append(certs, caddytls.Certificate{Certificate: *cert, Tags: entry.Tags})
	}
	return certs, nil
}

// Cleanup releases every KMS handle the loader holds.
func (l *Loader) Cleanup() error {
	var errs []error
	for i := range *l {
		src := (*l)[i].src
		if src == nil {
			continue
		}
		errs = append(errs, src.Close())
		(*l)[i].src = nil
	}
	return errors.Join(errs...)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler, appending one entry.
func (l *Loader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var e Entry
	if err := e.UnmarshalCaddyfile(d); err != nil {
		return err
	}
	*l = append(*l, e)
	return nil
}

// Interface guards
var (
	_ caddytls.CertificateLoader = (*Loader)(nil)
	_ caddy.Provisioner          = (*Loader)(nil)
	_ caddy.CleanerUpper         = (*Loader)(nil)
	_ caddyfile.Unmarshaler      = (*Loader)(nil)
)
