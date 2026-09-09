package fakekms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
)

func TestNewImplementsKeyManager(t *testing.T) {
	km := New(t, "example.com")

	var _ apiv1.KeyManager = km

	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "fake:name=x"})
	if err != nil {
		t.Fatalf("CreateSigner: %v", err)
	}
	if got := km.Signers.Load(); got != 1 {
		t.Errorf("Signers = %d, want 1", got)
	}
	if !km.Chain[0].PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	}).Equal(signer.Public()) {
		t.Error("certificate public key does not match signer")
	}
}

func TestChainManagerImplementsBothCertificateInterfaces(t *testing.T) {
	cm := &ChainManager{&CertManager{New(t, "example.com")}}

	var _ apiv1.CertificateManager = cm
	var _ apiv1.CertificateChainManager = cm

	chain, err := cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{Name: "fake:name=x"})
	if err != nil {
		t.Fatalf("LoadCertificateChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("len(chain) = %d, want 1", len(chain))
	}
}

func TestRefusePSSRejectsPSSButAllowsPKCS1(t *testing.T) {
	km := NewRSA(t, "example.com")
	signer := RefusePSS(km.Signer)
	sum := sha256.Sum256([]byte("x"))

	if _, err := signer.Sign(rand.Reader, sum[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}); err == nil {
		t.Error("PSS signing succeeded, want error")
	}
	if _, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256); err != nil {
		t.Errorf("PKCS#1 signing failed: %v", err)
	}
}
