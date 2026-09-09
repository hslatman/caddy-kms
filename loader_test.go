package caddykms

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.step.sm/crypto/kms/apiv1"

	"github.com/hslatman/caddy-kms/internal/fakekms"
)

// testContext returns a caddy.Context suitable for provisioning a module.
func testContext(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

func TestLoaderIsASliceType(t *testing.T) {
	// buildTLSApp groups certificate loaders with exactly this check and
	// silently discards any loader whose kind is not reflect.Slice. A
	// non-slice Loader would produce no certificate and no error at all, so
	// the same check is asserted here rather than trusted to a comment.
	//
	// Note this cannot be written as a type assertion to []Entry: assertions
	// require identical dynamic types, and Loader is a distinct named type.
	if kind := reflect.TypeOf(Loader{}).Kind(); kind != reflect.Slice {
		t.Fatalf("reflect.TypeOf(Loader{}).Kind() = %v, want %v", kind, reflect.Slice)
	}
}

func TestLoaderLoadCertificates(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	withPool(t, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})

	l := Loader{{Key: "tpmkms:name=a", Certificate: path, Tags: []string{"internal"}}}
	if err := l.Provision(testContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = l.Cleanup() })

	certs, err := l.LoadCertificates()
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Leaf == nil {
		t.Error("Leaf is nil")
	}
	if len(certs[0].Tags) != 1 || certs[0].Tags[0] != "internal" {
		t.Errorf("Tags = %v, want [internal]", certs[0].Tags)
	}

	var _ caddytls.CertificateLoader = &l
}

func TestLoaderProvisionFailsOnInvalidEntry(t *testing.T) {
	l := Loader{{Key: "tpmkms:path=/k.pem"}}

	err := l.Provision(testContext(t))
	if !errors.Is(err, errPathNeedsCertificate) {
		t.Errorf("Provision() = %v, want errPathNeedsCertificate", err)
	}
}

func TestLoaderCleanupClosesKeyManager(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	withPool(t, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})

	l := Loader{{Key: "tpmkms:name=a", Certificate: path}}
	if err := l.Provision(testContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := l.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if got := km.Closes.Load(); got != 1 {
		t.Errorf("Closes = %d, want 1", got)
	}
}

func TestLoaderSharesOneKeyManagerAcrossEntries(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	var opens int
	withPool(t, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		opens++
		return km, nil
	})

	l := Loader{
		{Key: "tpmkms:name=a", Certificate: path},
		{Key: "tpmkms:name=a", Certificate: path},
	}
	if err := l.Provision(testContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = l.Cleanup() })

	if opens != 1 {
		t.Errorf("opened %d key managers, want 1", opens)
	}
}

func TestLoaderUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		kms_certificate tpmkms:name=caddy-tls {
			certificate /etc/caddy/tls.crt
		}`)

	var l Loader
	if err := l.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if len(l) != 1 {
		t.Fatalf("len(l) = %d, want 1", len(l))
	}
	if l[0].Key != "tpmkms:name=caddy-tls" {
		t.Errorf("Key = %q", l[0].Key)
	}
	if l[0].Certificate != "/etc/caddy/tls.crt" {
		t.Errorf("Certificate = %q", l[0].Certificate)
	}
}
