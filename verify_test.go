package caddykms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/hslatman/caddy-kms/internal/fakekms"
)

func TestVerifyKeyPairAcceptsMatchingECDSAKey(t *testing.T) {
	km := fakekms.New(t, "example.com")

	if err := verifyKeyPair(km.Chain[0], km.Signer); err != nil {
		t.Errorf("verifyKeyPair() = %v, want nil", err)
	}
}

func TestVerifyKeyPairAcceptsMatchingRSAKey(t *testing.T) {
	km := fakekms.NewRSA(t, "example.com")

	if err := verifyKeyPair(km.Chain[0], km.Signer); err != nil {
		t.Errorf("verifyKeyPair() = %v, want nil", err)
	}
}

func TestVerifyKeyPairRejectsMismatchedKey(t *testing.T) {
	km := fakekms.New(t, "example.com")
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	err = verifyKeyPair(km.Chain[0], other)
	if !errors.Is(err, errKeyMismatch) {
		t.Errorf("verifyKeyPair() = %v, want errKeyMismatch", err)
	}
}

func TestVerifyKeyPairRejectsRSAKeyThatCannotDoPSS(t *testing.T) {
	km := fakekms.NewRSA(t, "example.com")

	err := verifyKeyPair(km.Chain[0], fakekms.RefusePSS(km.Signer))
	if !errors.Is(err, errNoPSS) {
		t.Errorf("verifyKeyPair() = %v, want errNoPSS", err)
	}
}
