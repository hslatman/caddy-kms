package caddykms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSoftKMSKeypair generates an ECDSA P-256 key and a self-signed
// certificate for "localhost", writes both as PEM, and returns their paths.
func writeSoftKMSKeypair(t *testing.T) (keyPath, certPath string, roots *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "tls.key")
	certPath = filepath.Join(dir, "tls.crt")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: keyDER,
	}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return keyPath, certPath, roots
}

// TestKMSBackedSignerCompletesTLS13Handshake drives the real code path: the
// loader resolves a certificate through softkms, and the resulting
// tls.Certificate — whose PrivateKey is an opaque crypto.Signer, not key
// material — serves a genuine TLS 1.3 handshake.
func TestKMSBackedSignerCompletesTLS13Handshake(t *testing.T) {
	keyPath, certPath, roots := writeSoftKMSKeypair(t)

	l := Loader{{Key: "softkms:" + keyPath, Certificate: certPath}}
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

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from a kms-backed key")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs[0].Certificate},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots,
		// httptest replaces the listener address, so the server name is set
		// explicitly to match the certificate rather than the dialled IP.
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}}}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(body) != "hello from a kms-backed key" {
		t.Errorf("body = %q", body)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = %x, want TLS 1.3", resp.TLS.Version)
	}
}

// TestKMSBackedCertificateUsesAnOpaqueSigner guards against the end-to-end test
// passing with the module effectively bypassed: the private key must be a
// signer whose public half matches the served leaf, never extracted key
// material.
func TestKMSBackedCertificateUsesAnOpaqueSigner(t *testing.T) {
	keyPath, certPath, _ := writeSoftKMSKeypair(t)

	l := Loader{{Key: "softkms:" + keyPath, Certificate: certPath}}
	if err := l.Provision(testContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = l.Cleanup() })

	certs, err := l.LoadCertificates()
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}

	signer, ok := certs[0].PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("PrivateKey is %T, want a crypto.Signer", certs[0].PrivateKey)
	}
	leafPub, ok := certs[0].Leaf.PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		t.Fatalf("unexpected leaf public key type %T", certs[0].Leaf.PublicKey)
	}
	if !leafPub.Equal(signer.Public()) {
		t.Error("signer public key does not match the served leaf")
	}
}
