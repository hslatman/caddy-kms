package caddykms

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-kms/internal/fakekms"
)

// writeChainPEM writes chain to a PEM file in a temp dir and returns its path.
func writeChainPEM(t *testing.T, chain []*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls.crt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	defer f.Close()
	for _, c := range chain {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatalf("encoding pem: %v", err)
		}
	}
	return path
}

// newTestSource builds a Source over km, with the pool wired to return it.
func newTestSource(t *testing.T, e Entry, km apiv1.KeyManager) *Source {
	t.Helper()
	p := newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})
	src, err := newSource(e, p, zap.NewNop())
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	if err := src.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src
}

func TestSourceResolveLoadsChainFromFile(t *testing.T) {
	km := fakekms.New(t, "example.com")
	path := writeChainPEM(t, km.Chain)
	src := newTestSource(t, Entry{Key: "tpmkms:name=a", Certificate: path}, km)

	cert, err := src.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(cert.Certificate) != 1 {
		t.Errorf("len(Certificate) = %d, want 1", len(cert.Certificate))
	}
	if cert.Leaf == nil {
		t.Error("Leaf is nil; it must be set so certificate selection works")
	}
	if cert.PrivateKey != km.Signer {
		t.Error("PrivateKey is not the KMS signer")
	}
	if got := km.Loads.Load(); got != 0 {
		t.Errorf("Loads = %d, want 0 when the certificate comes from a file", got)
	}
}

func TestSourceResolveLoadsChainFromChainManager(t *testing.T) {
	km := &fakekms.ChainManager{CertManager: &fakekms.CertManager{KeyManager: fakekms.New(t, "example.com")}}
	src := newTestSource(t, Entry{Key: "tpmkms:name=a"}, km)

	cert, err := src.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(cert.Certificate) != 1 {
		t.Errorf("len(Certificate) = %d, want 1", len(cert.Certificate))
	}
	if got := km.Loads.Load(); got != 1 {
		t.Errorf("Loads = %d, want 1", got)
	}
}

func TestSourceResolveFallsBackToCertificateManager(t *testing.T) {
	km := &fakekms.CertManager{KeyManager: fakekms.New(t, "example.com")}
	src := newTestSource(t, Entry{Key: "tpmkms:name=a"}, km)

	cert, err := src.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(cert.Certificate) != 1 {
		t.Errorf("len(Certificate) = %d, want 1", len(cert.Certificate))
	}
}

func TestSourceResolveRejectsBackendWithNoCertificateSource(t *testing.T) {
	km := fakekms.New(t, "example.com")
	src := newTestSource(t, Entry{Key: "tpmkms:name=a"}, km)

	_, err := src.Resolve()
	if !errors.Is(err, errNoCertificateSource) {
		t.Errorf("Resolve() = %v, want errNoCertificateSource", err)
	}
}

func TestSourceResolveRejectsMismatchedKey(t *testing.T) {
	km := fakekms.New(t, "example.com")
	other := fakekms.New(t, "example.com")
	path := writeChainPEM(t, other.Chain)
	src := newTestSource(t, Entry{Key: "tpmkms:name=a", Certificate: path}, km)

	_, err := src.Resolve()
	if !errors.Is(err, errKeyMismatch) {
		t.Errorf("Resolve() = %v, want errKeyMismatch", err)
	}
}

func TestSourceResolveRejectsRSAKeyThatCannotDoPSS(t *testing.T) {
	km := fakekms.NewRSA(t, "example.com")
	km.Signer = fakekms.RefusePSS(km.Signer)
	path := writeChainPEM(t, km.Chain)
	src := newTestSource(t, Entry{Key: "tpmkms:name=a", Certificate: path}, km)

	_, err := src.Resolve()
	if !errors.Is(err, errNoPSS) {
		t.Errorf("Resolve() = %v, want errNoPSS", err)
	}
}

func TestNewSourceRejectsInvalidEntry(t *testing.T) {
	_, err := newSource(Entry{Key: "tpmkms:path=/k.pem"}, defaultPool, zap.NewNop())
	if !errors.Is(err, errPathNeedsCertificate) {
		t.Errorf("newSource() = %v, want errPathNeedsCertificate", err)
	}
}

func TestChainFromFileRejectsFileWithoutCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(path, []byte("not pem at all\n"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if _, err := chainFromFile(path); err == nil {
		t.Error("chainFromFile() = nil error, want an error for a file with no CERTIFICATE block")
	}
}

func TestChainFromFileKeepsChainOrder(t *testing.T) {
	leaf := fakekms.New(t, "example.com")
	intermediate := fakekms.New(t, "ca.example.com")
	path := writeChainPEM(t, []*x509.Certificate{leaf.Chain[0], intermediate.Chain[0]})

	chain, err := chainFromFile(path)
	if err != nil {
		t.Fatalf("chainFromFile: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("len(chain) = %d, want 2", len(chain))
	}
	if !chain[0].Equal(leaf.Chain[0]) {
		t.Error("chain[0] is not the leaf")
	}
}
