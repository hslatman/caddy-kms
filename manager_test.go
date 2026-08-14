package caddykms

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.step.sm/crypto/kms/apiv1"

	"github.com/hslatman/caddy-kms/internal/fakekms"
)

// newTestManager provisions a Manager over km with a controllable clock.
func newTestManager(t *testing.T, km apiv1.KeyManager, e Entry, now func() time.Time) *Manager {
	t.Helper()
	withPool(t, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})
	m := &Manager{Entry: e, now: now}
	if err := m.Provision(testContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })
	return m
}

func TestManagerServesMatchingSNI(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a", Certificate: path}, time.Now)

	cert, err := m.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil for a matching name")
	}

	var _ certmagic.Manager = m
}

func TestManagerDeclinesNonMatchingSNI(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a", Certificate: path}, time.Now)

	// Declining must be (nil, nil), not an error: certmagic then lets other
	// managers and issuers try.
	cert, err := m.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "other.com"})
	if err != nil {
		t.Errorf("GetCertificate() error = %v, want nil", err)
	}
	if cert != nil {
		t.Error("GetCertificate returned a certificate for a non-matching name")
	}
}

func TestManagerCachesWithinTTL(t *testing.T) {
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: fakekms.New(t, "example.com")}}
	clock := time.Now()
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a"}, func() time.Time { return clock })
	m.TTL = caddy.Duration(5 * time.Minute)

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	for range 3 {
		if _, err := m.GetCertificate(context.Background(), hello); err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
	}

	if got := km.Loads.Load(); got != 1 {
		t.Errorf("Loads = %d within the TTL, want 1", got)
	}
}

func TestManagerRefreshesAfterTTL(t *testing.T) {
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: fakekms.New(t, "example.com")}}
	clock := time.Now()
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a"}, func() time.Time { return clock })
	m.TTL = caddy.Duration(5 * time.Minute)

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	if _, err := m.GetCertificate(context.Background(), hello); err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}
	clock = clock.Add(6 * time.Minute)
	if _, err := m.GetCertificate(context.Background(), hello); err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}

	if got := km.Loads.Load(); got != 2 {
		t.Errorf("Loads = %d after the TTL expired, want 2", got)
	}
}

func TestManagerServesStaleCertificateWhenRefreshFails(t *testing.T) {
	inner := fakekms.New(t, "example.com")
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: inner}}
	clock := time.Now()
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a"}, func() time.Time { return clock })
	m.TTL = caddy.Duration(5 * time.Minute)

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	first, err := m.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	inner.LoadErr = errors.New("tpm is busy")
	clock = clock.Add(6 * time.Minute)

	second, err := m.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("GetCertificate after a failed refresh: %v", err)
	}
	if second != first {
		t.Error("did not serve the last known good certificate")
	}
}

func TestManagerReturnsErrorWhenFirstResolveFails(t *testing.T) {
	inner := fakekms.New(t, "example.com")
	inner.LoadErr = errors.New("tpm is busy")
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: inner}}
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a"}, time.Now)

	if _, err := m.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Error("GetCertificate() = nil error, want an error when there is nothing to serve")
	}
}

func TestManagerCollapsesConcurrentResolves(t *testing.T) {
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: fakekms.New(t, "example.com")}}
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a"}, time.Now)

	var wg sync.WaitGroup
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.GetCertificate(context.Background(), hello); err != nil {
				t.Errorf("GetCertificate: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := km.Loads.Load(); got != 1 {
		t.Errorf("Loads = %d, want 1; concurrent handshakes must collapse into one KMS read", got)
	}
}

func TestManagerProvisionAppliesDefaultTTL(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	m := newTestManager(t, km, Entry{Key: "tpmkms:name=a", Certificate: path}, time.Now)

	if time.Duration(m.TTL) != defaultTTL {
		t.Errorf("TTL = %v, want the default %v", time.Duration(m.TTL), defaultTTL)
	}
}

func TestManagerUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		kms tpmkms:name=caddy-tls {
			certificate /etc/caddy/tls.crt
			ttl         90s
		}`)

	var m Manager
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if m.Key != "tpmkms:name=caddy-tls" {
		t.Errorf("Key = %q", m.Key)
	}
	if m.Certificate != "/etc/caddy/tls.crt" {
		t.Errorf("Certificate = %q", m.Certificate)
	}
	if time.Duration(m.TTL) != 90*time.Second {
		t.Errorf("TTL = %v, want 90s", time.Duration(m.TTL))
	}
}

func TestManagerUnmarshalCaddyfileRejectsUnknownSubdirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		kms tpmkms:name=caddy-tls {
			nonsense yes
		}`)

	var m Manager
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Error("UnmarshalCaddyfile() = nil error, want an error for an unknown subdirective")
	}
}
