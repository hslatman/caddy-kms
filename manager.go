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
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	// defaultTTL is how long a resolved certificate is served before it is
	// re-read from the KMS.
	defaultTTL = 5 * time.Minute

	// errorRetryInterval is how long a stale certificate is served after a
	// failed refresh, before the KMS is tried again. It exists so that a
	// failing KMS is not hammered once per handshake.
	errorRetryInterval = 30 * time.Second
)

func init() {
	caddy.RegisterModule(new(Manager))
}

// Manager serves a certificate whose private key lives in a KMS, re-reading it
// from the KMS at most once per TTL.
//
// Use this instead of tls.certificates.load_kms when a certificate rotated
// outside Caddy has to be picked up without a reload. Note that certmagic
// consults managers only after both in-memory cache lookups miss, so a name
// already covered by a loaded certificate never reaches a manager: the two are
// alternatives for a given name rather than layers.
//
// certmagic does not cache what a manager returns, so this is called on every
// handshake for the names it serves. Refreshes are collapsed so that a burst of
// connections causes one KMS read, and a failed refresh keeps serving the last
// known good certificate rather than failing handshakes.
type Manager struct {
	Entry

	// TTL is how long a resolved certificate is served before the KMS is read
	// again. Defaults to 5m. Tags are ignored by the manager.
	TTL caddy.Duration `json:"ttl,omitempty"`

	log   *zap.Logger
	group singleflight.Group
	cur   atomic.Pointer[cachedCertificate]
	now   func() time.Time
}

// cachedCertificate is a resolved certificate together with the time at which
// it should be refreshed.
type cachedCertificate struct {
	cert  *tls.Certificate
	until time.Time
}

// CaddyModule returns the Caddy module information.
func (*Manager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.kms",
		New: func() caddy.Module { return new(Manager) },
	}
}

// Provision opens the KMS and validates the configuration, so that problems
// abort the config load rather than surfacing per handshake.
func (m *Manager) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}
	m.log = ctx.Logger()
	if m.now == nil {
		m.now = time.Now
	}
	if m.TTL <= 0 {
		m.TTL = caddy.Duration(defaultTTL)
	}

	entry := m.Entry.replace(repl)
	src, err := newSource(entry, defaultPool, m.log)
	if err != nil {
		return err
	}
	if err := src.Open(ctx); err != nil {
		return err
	}
	entry.src = src
	m.Entry = entry
	return nil
}

// Cleanup releases the KMS handle.
func (m *Manager) Cleanup() error {
	if m.src == nil {
		return nil
	}
	return m.src.Close()
}

// GetCertificate implements certmagic.Manager. It returns (nil, nil) for names
// it has no certificate for, so that other managers and issuers still get a
// chance.
func (m *Manager) GetCertificate(_ context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := m.certificate()
	if err != nil {
		return nil, err
	}
	if !matchesSNI(cert.Leaf, hello.ServerName) {
		return nil, nil
	}
	return cert, nil
}

// certificate returns the cached certificate, refreshing it if the TTL has
// passed.
func (m *Manager) certificate() (*tls.Certificate, error) {
	if cached := m.cur.Load(); cached != nil && m.now().Before(cached.until) {
		return cached.cert, nil
	}

	value, err, _ := m.group.Do("resolve", func() (any, error) {
		// Another goroutine may have refreshed while this one queued.
		if cached := m.cur.Load(); cached != nil && m.now().Before(cached.until) {
			return cached.cert, nil
		}

		cert, err := m.src.Resolve()
		if err != nil {
			return m.stale(err)
		}
		m.cur.Store(&cachedCertificate{cert: cert, until: m.now().Add(time.Duration(m.TTL))})
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*tls.Certificate), nil
}

// stale serves the last known good certificate after a failed refresh, so that
// a KMS outage does not become a handshake outage. It gives up only when there
// is nothing usable to serve.
func (m *Manager) stale(cause error) (*tls.Certificate, error) {
	cached := m.cur.Load()
	if cached == nil || !m.now().Before(cached.cert.Leaf.NotAfter) {
		return nil, cause
	}
	m.log.Warn("refreshing kms certificate failed; serving the last known good certificate",
		zap.String("key", m.Key),
		zap.Time("not_after", cached.cert.Leaf.NotAfter),
		zap.Error(cause))
	m.cur.Store(&cachedCertificate{cert: cached.cert, until: m.now().Add(errorRetryInterval)})
	return cached.cert, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler, parsing:
//
//	get_certificate kms <key-uri> {
//	    certificate       <path>
//	    pin               <pin>
//	    storage_directory <path>
//	    ttl               <duration>
//	}
func (m *Manager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name
	if !d.NextArg() {
		return d.ArgErr()
	}
	m.Key = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		if d.Val() == "ttl" {
			if !d.NextArg() {
				return d.ArgErr()
			}
			ttl, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing ttl: %v", err)
			}
			m.TTL = caddy.Duration(ttl)
			continue
		}
		known, err := m.Entry.unmarshalOption(d)
		if err != nil {
			return err
		}
		if !known {
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*Manager)(nil)
	_ caddy.Provisioner     = (*Manager)(nil)
	_ caddy.CleanerUpper    = (*Manager)(nil)
	_ caddyfile.Unmarshaler = (*Manager)(nil)
)
