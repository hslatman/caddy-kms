# caddy-kms

A [Caddy](https://github.com/caddyserver/caddy) module that serves TLS from a
certificate whose private key never leaves a key management system — a TPM, a
PKCS #11 token, or a cloud KMS — using the KMS abstraction from
[`smallstep/crypto`](https://github.com/smallstep/crypto/tree/master/kms).

The key and certificate are provisioned and rotated outside Caddy. Caddy is a
consumer only: no ACME, no issuance, no renewal.

## Install

```
xcaddy build --with github.com/hslatman/caddy-kms
```

The default build is pure Go and needs no cgo. It registers two KMS backends,
`tpmkms` and `softkms`.

## Quick start

```
example.com {
    kms_certificate tpmkms:name=caddy-tls {
        certificate       /etc/caddy/tls.crt
        storage_directory /etc/step/tpm
    }
}
```

That is enough to stop Caddy managing certificates for `example.com`. Caddy
skips automatic management for any name it already holds a certificate for, so
you do not need `auto_https off` or an `automation` policy to prevent ACME.

## Configuration

| Field | Caddyfile | Required | Meaning |
|---|---|---|---|
| `key` | first argument | yes | KMS URI; the scheme selects the backend |
| `certificate` | `certificate` | no | Path to a PEM file. Omit to load the chain from the KMS. |
| `kms.pin` | `pin` | no | Passed to the backend as its PIN |
| `kms.storage_directory` | `storage_directory` | no | Where the TPM KMS keeps its serialized objects |
| `tags` | `tags` | no | Caddy certificate tags, for explicit selection. **Loader only.** |
| `ttl` | `ttl` | no | Cache lifetime before re-reading from the KMS. **Manager only**, default `5m`. |

All string fields go through Caddy's replacer, so `{env.*}` placeholders work.

The `key` URI does double duty, exactly as `step`'s `ca.json` does it: its
scheme selects the backend, any backend parameters it carries are honoured, and
its `name=` identifies the key. Backends ignore URI parameters they do not
recognise, which is what makes one field sufficient.

### JSON

```json
{"apps": {"tls": {"certificates": {"load_kms": [
  {
    "key": "tpmkms:name=caddy-tls",
    "certificate": "/etc/caddy/tls.crt",
    "kms": {"storage_directory": "/etc/step/tpm"},
    "tags": ["internal"]
  }
]}}}}
```

## Loader or manager?

Two modules are available, and choosing wrong fails quietly, so it is worth a
moment.

**`kms_certificate` / `tls.certificates.load_kms`** resolves the certificate
once, at config load, and hands it to Caddy's cache. Picking up a certificate
rotated outside Caddy needs a `caddy reload`. This is the right default.

**`get_certificate kms` / `tls.get_certificate.kms`** is consulted during the
handshake and re-reads the KMS at most once per `ttl`, so an externally rotated
certificate appears without a reload.

```
example.com {
    tls {
        get_certificate kms tpmkms:name=caddy-tls {
            certificate /etc/caddy/tls.crt
            ttl         5m
        }
    }
}
```

They are **alternatives for a given hostname, not layers.** CertMagic resolves
certificates in the order: exact cache match, wildcard cache match, managers,
storage, issuers. A name already covered by a loaded certificate therefore never
reaches a manager. Configuring both for the same name silently exercises only
the loader.

## Operational characteristics

These are inherent to keeping the key in hardware, not defects. Read them before
deploying.

**Every handshake costs one KMS signature.** With a TPM that is an open, a key
load, a sign, and a close — serialized across the whole process by a mutex, and
taking tens to hundreds of milliseconds. This caps handshake throughput, and no
module structure can avoid it. Enable TLS session resumption. Measure your
device before sizing anything; see [the hardware
checklist](docs/hardware-checklist.md).

**`caddy validate` needs KMS access.** Validation happens at config load, so
`validate` and every `reload` open the KMS and perform one test signature per
certificate. A CI machine without a TPM cannot validate a TPM config.

**A hostless, non-standard-port site needs TLS enabled explicitly.** On
something like `:8443`, `kms_certificate` alone does not turn on TLS, because it
emits no connection policy. Use `https://` or add a `tls` block. This is the
same caveat that already applies to `tls <cert> <key>`.

**A catch-all site using `get_certificate kms` logs a warning** saying
certificates can only come from the configured external managers. That is the
intended state, not a misconfiguration.

## Key requirements

**ECDSA P-256 is the safe choice.**

An RSA key must be able to produce **PSS** signatures, because TLS 1.3 requires
them. A TPM RSA key created with the RSASSA scheme cannot, and would fail every
TLS 1.3 handshake. The module signs once at config load to check, and rejects
such a key with an error saying so rather than letting it fail at handshake time.

A key identified by `path=` — a TSS2 PEM file — can be used for signing but
cannot supply its own certificate, because `LoadCertificateChain` requires
`name=`. Pair it with `certificate`.

## Adding a KMS backend

Add one blank import to `backends.go`. No other code is backend-specific;
certificate loading is selected by interface assertion, never by backend name.

Note that `pkcs11`, `yubikey` and `mackms` need cgo. `go.step.sm/crypto` ships
`nopkcs11`, `noyubikey`, `nomackms`, `noawskms` and `noazurekms` build tags for
trimming a wider backend set back down.

## Development

```
make test       # cgo-free, no hardware
make test-race
make test-tpm   # TPM simulator; needs cgo and libssl-dev
make lint
make build      # xcaddy build, checks the plugin registers
```

## Links

- [Design document](docs/superpowers/specs/2026-08-14-caddy-kms-design.md) — architecture, and the upstream behaviour this module depends on
- [`smallstep/crypto`](https://github.com/smallstep/crypto)
- [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin) — creates and manages the keys this module consumes
- [Caddy](https://caddyserver.com)

## License

Apache-2.0
