package caddykms

import (
	"errors"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.step.sm/crypto/kms/apiv1"
)

func TestEntryOptionsInfersTypeFromURIScheme(t *testing.T) {
	e := Entry{Key: "tpmkms:name=caddy-tls", KMS: &KMSOptions{StorageDirectory: "/etc/step/tpm"}}

	opts, err := e.options()
	if err != nil {
		t.Fatalf("options(): %v", err)
	}
	if opts.Type != apiv1.TPMKMS {
		t.Errorf("Type = %q, want %q", opts.Type, apiv1.TPMKMS)
	}
	if opts.URI != "tpmkms:name=caddy-tls" {
		t.Errorf("URI = %q, want the key URI", opts.URI)
	}
	if opts.StorageDirectory != "/etc/step/tpm" {
		t.Errorf("StorageDirectory = %q, want /etc/step/tpm", opts.StorageDirectory)
	}
}

func TestEntryOptionsRejectsURIWithoutScheme(t *testing.T) {
	e := Entry{Key: "/etc/caddy/key.pem"}

	if _, err := e.options(); err == nil {
		t.Error("options() = nil error, want an error for a missing scheme")
	}
}

func TestEntryValidateRejectsPathKeyWithoutCertificate(t *testing.T) {
	e := Entry{Key: "tpmkms:path=/etc/step/key.tss2.pem"}

	if err := e.validate(); !errors.Is(err, errPathNeedsCertificate) {
		t.Errorf("validate() = %v, want errPathNeedsCertificate", err)
	}
}

func TestEntryValidateAcceptsPathKeyWithCertificate(t *testing.T) {
	e := Entry{Key: "tpmkms:path=/etc/step/key.tss2.pem", Certificate: "/etc/caddy/tls.crt"}

	if err := e.validate(); err != nil {
		t.Errorf("validate() = %v, want nil", err)
	}
}

func TestEntryValidateRejectsEmptyKey(t *testing.T) {
	if err := (Entry{}).validate(); err == nil {
		t.Error("validate() = nil error, want an error for an empty key")
	}
}

func TestEntryReplaceExpandsPlaceholders(t *testing.T) {
	t.Setenv("CADDY_KMS_TEST_DIR", "/var/lib/step/tpm")
	repl := caddy.NewReplacer()
	e := Entry{
		Key:         "tpmkms:name=caddy-tls",
		Certificate: "{env.CADDY_KMS_TEST_DIR}/tls.crt",
		KMS:         &KMSOptions{StorageDirectory: "{env.CADDY_KMS_TEST_DIR}"},
		Tags:        []string{"{env.CADDY_KMS_TEST_DIR}"},
	}

	got := e.replace(repl)

	if got.Certificate != "/var/lib/step/tpm/tls.crt" {
		t.Errorf("Certificate = %q", got.Certificate)
	}
	if got.KMS.StorageDirectory != "/var/lib/step/tpm" {
		t.Errorf("StorageDirectory = %q", got.KMS.StorageDirectory)
	}
	if got.Tags[0] != "/var/lib/step/tpm" {
		t.Errorf("Tags[0] = %q", got.Tags[0])
	}
	if e.KMS.StorageDirectory != "{env.CADDY_KMS_TEST_DIR}" {
		t.Error("replace mutated the receiver's KMS options")
	}
}

func TestEntryUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		kms_certificate tpmkms:name=caddy-tls {
			certificate       /etc/caddy/tls.crt
			pin               1234
			storage_directory /etc/step/tpm
			tags              internal shared
		}`)

	var e Entry
	if err := e.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if e.Key != "tpmkms:name=caddy-tls" {
		t.Errorf("Key = %q", e.Key)
	}
	if e.Certificate != "/etc/caddy/tls.crt" {
		t.Errorf("Certificate = %q", e.Certificate)
	}
	if e.KMS.Pin != "1234" {
		t.Errorf("Pin = %q", e.KMS.Pin)
	}
	if e.KMS.StorageDirectory != "/etc/step/tpm" {
		t.Errorf("StorageDirectory = %q", e.KMS.StorageDirectory)
	}
	if len(e.Tags) != 2 || e.Tags[0] != "internal" || e.Tags[1] != "shared" {
		t.Errorf("Tags = %v", e.Tags)
	}
}

func TestEntryUnmarshalCaddyfileRejectsUnknownSubdirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		kms_certificate tpmkms:name=caddy-tls {
			nonsense yes
		}`)

	var e Entry
	if err := e.UnmarshalCaddyfile(d); err == nil {
		t.Error("UnmarshalCaddyfile() = nil error, want an error for an unknown subdirective")
	}
}

func TestEntryUnmarshalCaddyfileRequiresKey(t *testing.T) {
	d := caddyfile.NewTestDispenser(`kms_certificate`)

	var e Entry
	if err := e.UnmarshalCaddyfile(d); err == nil {
		t.Error("UnmarshalCaddyfile() = nil error, want an error for a missing key")
	}
}
