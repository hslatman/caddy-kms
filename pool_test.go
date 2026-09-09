package caddykms

import (
	"context"
	"errors"
	"testing"

	"go.step.sm/crypto/kms/apiv1"

	"github.com/hslatman/caddy-kms/internal/fakekms"
)

// withPool swaps defaultPool for one backed by open, for the duration of the
// test. Tests must never reach a real KMS.
func withPool(t *testing.T, open openFunc) {
	t.Helper()
	prev := defaultPool
	defaultPool = newPool(open)
	t.Cleanup(func() { defaultPool = prev })
}

func TestPoolSharesOneKeyManagerPerOptions(t *testing.T) {
	km := fakekms.New(t, "example.com")
	var opens int
	p := newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		opens++
		return km, nil
	})
	opts := apiv1.Options{Type: apiv1.TPMKMS, URI: "tpmkms:name=a"}

	first, err := p.acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	second, err := p.acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}

	if opens != 1 {
		t.Errorf("opened %d key managers, want 1", opens)
	}
	if first != second {
		t.Error("acquire returned different key managers for the same options")
	}
}

func TestPoolOpensSeparateKeyManagersForDifferentOptions(t *testing.T) {
	var opens int
	p := newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		opens++
		return fakekms.New(t, "example.com"), nil
	})

	if _, err := p.acquire(context.Background(), apiv1.Options{URI: "tpmkms:name=a"}); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	if _, err := p.acquire(context.Background(), apiv1.Options{URI: "tpmkms:name=a", StorageDirectory: "/x"}); err != nil {
		t.Fatalf("acquire b: %v", err)
	}

	if opens != 2 {
		t.Errorf("opened %d key managers, want 2", opens)
	}
}

func TestPoolClosesKeyManagerOnLastRelease(t *testing.T) {
	km := fakekms.New(t, "example.com")
	p := newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})
	opts := apiv1.Options{URI: "tpmkms:name=a"}

	for range 2 {
		if _, err := p.acquire(context.Background(), opts); err != nil {
			t.Fatalf("acquire: %v", err)
		}
	}

	if err := p.release(opts); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if got := km.Closes.Load(); got != 0 {
		t.Errorf("Closes = %d after first release, want 0", got)
	}

	if err := p.release(opts); err != nil {
		t.Fatalf("second release: %v", err)
	}
	if got := km.Closes.Load(); got != 1 {
		t.Errorf("Closes = %d after last release, want 1", got)
	}
}

func TestPoolPropagatesOpenError(t *testing.T) {
	want := errors.New("no tpm device")
	p := newPool(func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return nil, want
	})

	_, err := p.acquire(context.Background(), apiv1.Options{URI: "tpmkms:name=a"})
	if !errors.Is(err, want) {
		t.Errorf("acquire() = %v, want %v", err, want)
	}
}
