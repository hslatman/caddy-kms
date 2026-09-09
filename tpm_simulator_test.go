//go:build tpmsimulator

package caddykms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

// TestLoaderAgainstTPMSimulator runs the loader against a simulated TPM,
// covering the tpmkms code path that the fake KeyManager cannot: key creation
// inside the TPM, a real TSS2 signer, and a certificate chain stored in TPM
// storage.
//
// Build with -tags tpmsimulator. The simulator needs cgo and go-tpm-tools, so
// this is not part of the default test run.
func TestLoaderAgainstTPMSimulator(t *testing.T) {
	sim, err := simulator.New()
	if err != nil {
		t.Fatalf("creating simulator: %v", err)
	}
	if err := sim.Open(); err != nil {
		t.Fatalf("opening simulator: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })

	instance, err := tpm.New(
		tpm.WithSimulator(sim),
		tpm.WithStore(newSimulatorStore(t)),
	)
	if err != nil {
		t.Fatalf("creating tpm: %v", err)
	}

	km, err := tpmkms.NewWithTPM(context.Background(), instance)
	if err != nil {
		t.Fatalf("creating tpmkms: %v", err)
	}

	const keyURI = "tpmkms:name=caddy-tls"
	if _, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               keyURI,
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	}); err != nil {
		t.Fatalf("creating key: %v", err)
	}

	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: keyURI})
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	chain := selfSignWithSigner(t, signer, "example.com")
	if err := km.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name:             keyURI,
		CertificateChain: chain,
	}); err != nil {
		t.Fatalf("storing certificate chain: %v", err)
	}

	// Point the pool at this simulator-backed KMS instead of real hardware.
	prev := defaultPool
	defaultPool = newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})
	t.Cleanup(func() { defaultPool = prev })

	l := Loader{{Key: keyURI}}
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
		t.Fatal("Leaf is nil")
	}
	if certs[0].Leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v", certs[0].Leaf.DNSNames)
	}

	// The private key must be a signer backed by the TPM, never extracted
	// key material.
	tpmSigner, ok := certs[0].PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("PrivateKey is %T, want a crypto.Signer", certs[0].PrivateKey)
	}
	leafPub, ok := certs[0].Leaf.PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		t.Fatalf("unexpected leaf public key type %T", certs[0].Leaf.PublicKey)
	}
	if !leafPub.Equal(tpmSigner.Public()) {
		t.Error("signer public key does not match the leaf")
	}
}

// newSimulatorStore returns a TPM object store rooted in a fresh temp
// directory, so each run starts from empty storage.
func newSimulatorStore(t *testing.T) storage.TPMStore {
	t.Helper()
	return storage.NewDirstore(t.TempDir())
}

// selfSignWithSigner issues a self-signed server certificate for dnsNames,
// signed by signer — here the TPM-resident key, so this also exercises TPM
// signing outside the TLS path.
func selfSignWithSigner(t *testing.T, signer crypto.Signer, dnsNames ...string) []*x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "caddy-kms tpm simulator"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return []*x509.Certificate{cert}
}
