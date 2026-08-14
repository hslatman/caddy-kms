# caddy-kms: KMS-backed certificates for Caddy

**Date:** 2026-08-14
**Status:** approved design, not yet implemented
**Module path:** `github.com/hslatman/caddy-kms`
**License:** Apache-2.0 (matching Caddy and `smallstep/crypto`)

## Context

Caddy can load certificates from disk, from its storage backend, or obtain them
automatically via ACME. It cannot use a private key that never leaves a hardware
security boundary — a TPM, a PKCS #11 token, or a cloud KMS.

This project adds that capability using the KMS abstraction in
[`go.step.sm/crypto/kms`](https://github.com/smallstep/crypto/tree/master/kms),
so the same module works across backends rather than being TPM-specific.

The private key and certificate are provisioned and rotated by tooling outside
Caddy (typically `step-kms-plugin`). Caddy is a consumer only: it must not
attempt ACME issuance or renewal for these names.

### Goals

- Serve TLS from a certificate whose private key stays inside a KMS, used
  through `crypto.Signer` and never extracted.
- Get the certificate chain from either the KMS or a PEM file, chosen per
  certificate.
- Suppress automatic certificate management for the covered names.
- Keep all module code KMS-agnostic, so adding a backend is an import line.
- Support both Caddyfile and JSON configuration.

### Non-goals

- Certificate issuance, renewal, or ACME of any kind.
- Key or certificate *creation* in the KMS. `CreateKey` and `StoreCertificate`
  are out of scope; external tooling owns the lifecycle.
- Client certificates, or KMS-backed keys for anything other than TLS server
  certificates.
- Attestation (`apiv1.Attester`).

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Certificate comes from a PEM file *or* the KMS, chosen per entry | TPM stores chains; `pkcs11`/`awskms`/`cloudkms` hold keys only. One config shape covers both. |
| D2 | Ship **both** a certificate loader and a `get_certificate` manager | The loader is the primary, simple path. The manager exists for picking up an externally rotated certificate without a reload. |
| D3 | Default build registers `tpmkms` and `softkms` only | Pure Go, small dependency tree, builds anywhere with plain `xcaddy`. `softkms` also makes hardware-free testing possible. |
| D4 | Manager refreshes lazily, on a TTL, at handshake time | Simpler than a background poller: no goroutine lifecycle. Mitigated by singleflight plus stale-on-error (see [Manager path](#manager-path-resolve-per-handshake)). |
| D5 | Config is URI-first: one `key` field, backend selected by URI scheme | Matches `step-kms-plugin` and `ca.json`, which users already know. `apiv1.TypeOf` does the scheme→type mapping. |
| D6 | KeyManagers are deduplicated inside the module, keyed by effective options | Not an optimization — see [Why the pool exists](#why-the-pool-exists). |
| D7 | Validate aggressively at provision time, including one test signature | Turns the two most common operator errors, and the RSA-PSS trap, into config-load failures instead of handshake failures. |

## Verified upstream behaviour

Every claim below was read from source at these versions, not inferred.
Implementation depends on all of them; re-check on major upgrades.

- **Caddy** v2.11.4
- **CertMagic** v0.25.3
- **`go.step.sm/crypto`** v0.87.0
- **Go** 1.26

### F1 — The certificate loader interface

`caddytls.CertificateLoader` is `LoadCertificates() ([]Certificate, error)`,
where `Certificate` embeds `tls.Certificate` and adds `Tags []string`. Modules
register in the `tls.certificates.*` namespace.

`modules/caddytls/tls.go:263-275` calls `LoadCertificates()` during **tls app
`Provision`**, caches each result with `CacheUnmanagedTLSCertificate`, and
returns a wrapped error on failure. So a loader error aborts config load, which
is the fail-fast behaviour D7 wants.

`tls.go:244` asserts the loaded module value to `CertificateLoader`. With
`New: func() caddy.Module { return new(Loader) }` that value is `*Loader`, so a
value-receiver method set on `Loader` satisfies both forms.

### F2 — ACME suppression is automatic

`modules/caddyhttp/autohttps.go:208` skips automatic management for a subject
when `!srv.AutoHTTPS.IgnoreLoadedCerts && app.tlsApp.HasCertificateForSubject(d)`.

The tls app provisions before the HTTP app runs auto-HTTPS, so a certificate
loaded per F1 is already in the cache by then. **Loading the certificate is
sufficient to suppress ACME.** Users do not need `auto_https off`, and the
module must not require it.

### F3 — The `tls` directive has no third-party loader hook

`caddyconfig/httpcaddyfile/builtins.go` `parseTLS` ends in
`default: return nil, h.Errf("unknown subdirective: %s", h.Val())`. Only the
built-in `<cert> <key>` and `load` forms produce certificate loaders.

Caddyfile support therefore requires registering an **own top-level directive**
via `httpcaddyfile.RegisterDirective`, returning a
`ConfigValue{Class: "tls.cert_loader", Value: …}`. `buildTLSApp` reads that pile
key at `tlsapp.go:288-291`.

`tls` is **not** in `defaultDirectiveOrder` (`directives.go:47-98`), which is the
list used only for ordering HTTP handler directives. A directive that emits no
handler needs no ordering entry, so `RegisterDirective` alone is enough.

### F4 — Loaders must be slice types, passed by value

`tlsapp.go:297-322` groups loaders by module name using reflection, guarded by:

```go
if reflect.TypeOf(cl).Kind() == reflect.Slice {
```

A loader whose dynamic type is not a slice is **silently dropped** — no error,
no warning, no certificate. `parseTLS` stores `caddytls.FileLoader` by value,
not as a pointer, which is what makes the check pass.

Two hard constraints follow: `Loader` must be defined as a slice type, and the
Caddyfile directive must put `Loader{…}` (value) into the `ConfigValue`, never
`&Loader{…}`. An adapter test guards this; see [Testing](#testing).

### F5 — Handshake resolution order, and managers are not cached

`certmagic/handshake.go:36-43` documents, and `getCertDuringHandshake`
implements, this order:

1. Exact match in the in-memory cache
2. Wildcard match in the in-memory cache
3. Managers, if any
4. Storage, if on-demand is enabled
5. Issuers, if on-demand is enabled

Managers are consulted at `handshake.go:342-352`, i.e. **only after both cache
lookups miss**. Two consequences:

- The loader and the manager are **alternatives per hostname, not layers.** If a
  loader has already cached a certificate covering the SNI, the manager for that
  name will never be called. Documentation must say so.
- Manager results are deliberately **not** added to the cache — see the comment
  at `handshake.go:316-320`. The manager is therefore invoked on *every*
  handshake for names it serves, which is why its internal cache is load-bearing
  rather than a nicety.

`Manager.GetCertificate` must return `(nil, nil)` when it has no certificate for
the handshake, so that other managers and issuers still get a turn
(`certmagic.go:350-360`).

### F6 — `get_certificate` implies on-demand, and does not require a permission module

`modules/caddytls/automation.go:295` builds the on-demand config when
`ap.OnDemand || len(ap.Managers) > 0`. Users configuring `get_certificate kms`
therefore do **not** need to set `on_demand`.

`automation.go:302-311`: when the policy is a wildcard or the default and no
permission module is configured, Caddy logs a warning that certificates can only
come from the configured external managers, and refuses issuance from Issuers
(`failClosed`). Because `hadExplicitManagers` is true for us, this is a warning,
not a config error. That outcome is exactly what this module wants; document it
so the warning isn't mistaken for a misconfiguration.

`automation.go:210-212` notes that policy provisioning "may happen more than
once (during auto-HTTPS)". `Manager.Provision` must therefore tolerate being
called on multiple instances for the same configuration.

### F7 — TPM signing opens the device per signature, under a global lock

`tpm/signer.go:28-53` — every `Sign` call opens the TPM, loads the key, signs,
and closes:

```go
func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	if err = s.tpm.open(ctx, openOptions{machineKey: s.key.machineKey}); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, s.tpm, &err)
	loadedKey, err := s.tpm.attestTPM.LoadKey(s.key.data)
	…
}
```

`tpm.TPM.open` takes `t.lock.Lock()` (`tpm/tpm.go:181`), a `sync.RWMutex` held
per `*tpm.TPM` instance. So all signing through one instance is **fully
serialized**, and the device is **not** held open between signatures.

This is the single most important operational fact about the module. It drives
D6, and it makes config reloads safe (no lingering device handle).

### F8 — One URI can serve as both KMS options and key name

`tpmkms.New` (`kms/tpmkms/tpmkms.go:420-445`) parses `opts.URI` with
`uri.ParseWithScheme` and hands it to `ParseOptions`, which reads only the
options it knows (`device`, `storage-directory`, and the Windows/attestation
settings). An unrecognised `name=` parameter is ignored.

Meanwhile `CreateSigner` (`tpmkms.go:737`) parses the *same* URI shape via
`parseNameURI` and uses `name=` to select the key.

So a single `key` value — `tpmkms:name=caddy-tls` — can be passed as both
`apiv1.Options.URI` and `CreateSignerRequest.SigningKey`. This is how `step`'s
`ca.json` already works, and it is what makes D5 viable.

### F9 — TPM certificate loading requires `name=`, not `path=`

`CreateSigner` accepts either `name=` (from smallstep TPM storage) or
`path=` (a TSS2 PEM file). But `LoadCertificateChain` (`tpmkms.go:872-928`)
requires `req.Name` and resolves it through `parseNameURI` → `getKey`/`getAK`;
there is no `path=` branch.

Therefore a `path=` key can never self-supply a certificate, and must be paired
with an explicit `certificate`. Rejected at provision time.

### F10 — Which backends implement which interfaces

`TPMKMS` satisfies `KeyManager`, `Attester`, `CertificateManager`,
`CertificateChainManager`, `CredentialsCleaner`, `CertificateDeleter`, and
`SearchableCertificateManager` (`tpmkms.go:1987-1994`).

`LoadCertificate` on TPMKMS is implemented in terms of `LoadCertificateChain`
and returns `chain[0]`, so the chain interface is the one worth preferring.

Most other backends implement only `KeyManager`. The module must degrade by
interface assertion, never by backend name.

### F11 — `tpmkms` defaults its storage directory relative to the working directory

`tpmkms.go:433-437`:

```go
storageDirectory := "tpm"
if opts.StorageDirectory != "" {
	storageDirectory = opts.StorageDirectory
}
```

For Caddy running as a service the working directory is unpredictable, and the
key was created by external tooling using *its* storage path. The module
deliberately does not invent a competing default; it logs the effective storage
directory at provision so a "key not found" is immediately diagnosable.

## Architecture

```
 Caddyfile: kms_certificate ──►┌─────────────────────────┐  tls.certificates.load_kms
                               │ Loader  ([]Entry)       │  resolved once, at tls-app
                               └────────────┬────────────┘  Provision; cached unmanaged
                                            │
                                     Resolve(ctx)
                                            │
                               ┌────────────▼────────────┐  open KMS → CreateSigner →
                               │ Source (shared)         │  chain from KMS or file →
                               └────────────┬────────────┘  validate → *tls.Certificate
                                            │
 tls { get_certificate kms } ──►┌───────────▼────────────┐  tls.get_certificate.kms
                               │ Manager (TTL cache)     │  consulted per handshake
                               └─────────────────────────┘
```

One shared resolver, two thin adapters. `Source` is the only type that touches
`go.step.sm/crypto`; both Caddy modules are adapters over it.

### File layout

| File | Responsibility |
|---|---|
| `source.go` | `Source.Resolve(ctx) (*tls.Certificate, error)` — the only code that touches `go.step.sm/crypto` |
| `pool.go` | KeyManager deduplication keyed by effective `apiv1.Options`; ref-counted, `Close()` on last release |
| `verify.go` | Leaf↔signer public-key equality, and the test signature |
| `loader.go` | `type Loader []Entry`; module `tls.certificates.load_kms` |
| `manager.go` | `type Manager struct{…}`; module `tls.get_certificate.kms`; TTL + singleflight + last-known-good |
| `caddyfile.go` | `httpcaddyfile.RegisterDirective("kms_certificate", …)` |
| `backends.go` | Blank imports of `tpmkms` and `softkms` |
| `internal/fakekms/` | Test double implementing `apiv1.KeyManager` and, selectably, the certificate interfaces |

### Why the pool exists

Per F7, all signing through one `*tpm.TPM` is serialized by a mutex on that
instance. Two independently constructed `TPMKMS` values hold two different
mutexes and therefore contend at the device or resource-manager level instead of
in Go, where the contention is neither ordered nor observable.

So deduplication is closer to correctness than to performance. The pool is keyed
by the effective `apiv1.Options` (type, URI, pin, storage directory), is
ref-counted, and closes the underlying `KeyManager` when the last holder
releases it. Ref-counting is required, not incidental: per F6, policy
provisioning can run more than once for the same configuration.

## Configuration

### Fields

| Field | JSON | Caddyfile | Required | Meaning |
|---|---|---|---|---|
| Key URI | `key` | first argument | yes | KMS URI; scheme selects the backend, e.g. `tpmkms:name=caddy-tls` |
| Certificate | `certificate` | `certificate` | no | Path to a PEM file. Omit to load the chain from the KMS. |
| Pin | `kms.pin` | `pin` | no | Passed through as `apiv1.Options.Pin` |
| Storage directory | `kms.storage_directory` | `storage_directory` | no | Passed through as `apiv1.Options.StorageDirectory` |
| Tags | `tags` | `tags` | no | Caddy certificate tags, for explicit selection. Loader only. |
| TTL | `ttl` | `ttl` | no | Manager only. Cache lifetime before re-reading from the KMS. Default `5m`. |

All string fields go through Caddy's replacer at provision, mirroring
`FileLoader.Provision`, so `{env.*}` placeholders work.

`Entry` is the shared configuration type: `Loader` is a slice of it (F4), and
`Manager` is one `Entry` plus `ttl` and the cache state. Both adapters therefore
accept the same key, certificate, and KMS fields, and `Source` is constructed
from an `Entry` identically in both paths.

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

### Caddyfile — loader

```
example.com {
    kms_certificate tpmkms:name=caddy-tls {
        certificate       /etc/caddy/tls.crt   # omit → chain comes from the TPM
        storage_directory /etc/step/tpm
        tags              internal
    }
}
```

### Caddyfile — manager

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

### Documented caveats

- Per F5, the loader and the manager are alternatives for a given hostname. A
  configuration with both for the same name silently exercises only the loader.
- Per F3/F4, `load_kms` is app-global like every Caddy certificate loader. SNI
  selects between entries; `tags` allow explicit selection from a connection
  policy.
- On a hostless, non-standard-port site such as `:8443`, `kms_certificate` alone
  does not enable TLS, because it emits no connection policy. This is the same
  caveat that already applies to `tls <cert> <key>`. Use `https://` or add a
  `tls` block.
- Per F6, a catch-all site using `get_certificate kms` will log a warning that
  certificates can only come from external managers. That is the intended state.
- `kms_certificate` may appear more than once, in one site block or across
  several. Each occurrence emits its own `tls.cert_loader` value, and
  `buildTLSApp` concatenates them into a single `load_kms` array (F4).
- When `certificate` is set, the manager's TTL re-read re-reads the *file*, not
  the KMS chain. External rotation of that file is therefore picked up within
  `ttl` as well.

## Data flow

### Loader path (resolve once)

1. Config load → tls app `Provision` → `LoadCertificates()` on `*Loader` (F1).
2. Per entry:
   1. Expand placeholders through the replacer.
   2. Build `apiv1.Options{URI: key, Pin: …, StorageDirectory: …}`; the type is
      inferred from the URI scheme by `Options.GetType()` → `apiv1.TypeOf` (F8).
   3. `pool.Acquire(opts)` → shared `apiv1.KeyManager` (D6).
   4. `km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: key})` →
      `crypto.Signer`.
   5. Resolve the chain:
      - `certificate` set → read the file, decode every `CERTIFICATE` block in
        order;
      - else `km` implements `apiv1.CertificateChainManager` →
        `LoadCertificateChain(&apiv1.LoadCertificateChainRequest{Name: key})`;
      - else `km` implements `apiv1.CertificateManager` → `LoadCertificate`,
        yielding a leaf-only chain;
      - else fail, naming the backend and pointing at `certificate` (F10).
   6. Validate (see [Validation](#validation-and-error-handling)).
   7. Build `tls.Certificate{Certificate: DERs, PrivateKey: signer, Leaf: leaf}`.
      `Leaf` is set explicitly because `DefaultCertificateSelector` and
      `SupportsCertificate` both read it.
3. Return `[]caddytls.Certificate` with tags. Caddy caches each as unmanaged.
4. Auto-HTTPS later finds `HasCertificateForSubject` true and skips ACME (F2).

At handshake time this path does nothing: Go's TLS stack calls `signer.Sign`
directly.

### Manager path (resolve per handshake)

Per F5 this runs on every handshake for names it serves.

1. Read an `atomic.Pointer` holding the cached certificate and its cache expiry.
2. If absent or expired, resolve through
   `golang.org/x/sync/singleflight` — already in the dependency tree — so a
   connection swarm produces one KMS read rather than thousands.
   - Success: store the new pointer, set expiry to `now + ttl`.
   - Failure with a still-valid last-known-good certificate: log at WARN, serve
     the stale certificate, and push the next attempt out by a backoff. A KMS
     hiccup must not become a handshake outage.
   - Failure with nothing to serve: return the error.
3. Match SNI against the leaf's DNS SANs (including `*.` wildcards) and IP SANs.
   No match returns `(nil, nil)`, per the `Manager` contract in F5.
4. `Manager` implements `caddy.CleanerUpper` to release its pooled KeyManager.

Time is injected as a `now func() time.Time` field so TTL behaviour is testable
without sleeping.

## Validation and error handling

Everything cheap to check happens at provision, where failure aborts config load
and the previous config keeps serving.

**Fail:**

- URI parse failure or unknown scheme → error listing compiled-in backends and
  how to add more (D3).
- `path=` key with no `certificate` → error (F9).
- Unreadable PEM, or no `CERTIFICATE` block in it.
- Backend implements neither certificate interface and no `certificate` is set
  (F10).
- **Key↔certificate binding:** `leaf.PublicKey` compared to `signer.Public()`
  via the `Equal(crypto.PublicKey) bool` method that Go's key types implement.
  This catches the two most likely operator errors — rotating the certificate
  without the key, and naming the wrong key.
- **Test signature.** Sign a fixed 32-byte digest and verify it against the
  leaf's public key: RSA with `rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash,
  Hash: crypto.SHA256}` verified by `rsa.VerifyPSS`; ECDSA by `ecdsa.VerifyASN1`;
  Ed25519 by signing the message directly and using `ed25519.Verify`. On failure
  the error states that a TPM RSA key created with the RSASSA scheme cannot
  produce PSS signatures and so cannot serve TLS 1.3, and suggests ECDSA P-256.
  Cost: one KMS signing operation per entry per config load.

**Warn, do not fail** — failing here would be hostile precisely when an operator
is recovering:

- Leaf already expired. Caddy's selector already prefers unexpired candidates.
- Chain intermediates not in issuer order. A wrong order breaks some clients, but
  rejecting outright would also reject legitimate cross-signed bundles.
- The effective `tpmkms` storage directory, logged unconditionally (F11).

**At runtime:** the loader path has no error surface of its own; signer failures
appear as handshake errors that Caddy already logs. The manager path is
stale-on-error as described above. Pool `Close()` errors are logged, never
propagated.

## Operational characteristics

These are inherent, not defects. They belong in the README.

- **Every handshake costs one KMS signature.** With a TPM that is an open, key
  load, sign, and close, fully serialized across the process (F7) — tens to
  hundreds of milliseconds. This caps handshake throughput regardless of module
  structure. TLS session resumption is the mitigation. Document the ceiling.
- **`caddy validate` needs KMS access.** `Provision` runs during validate and on
  every reload, so both require the TPM and each costs one open-load-sign-close
  per entry. A `verify_key: false` escape hatch was considered and rejected: it
  would not help, because `CreateSigner` already fails without a TPM, well
  before verification runs.
- **Rotation.** The loader picks up a rotated certificate on `caddy reload`. The
  manager picks it up within `ttl`.

## Testing

The single seam is an unexported field on `Source`:

```go
open func(context.Context, apiv1.Options) (apiv1.KeyManager, error) // defaults to kms.New
```

That one field makes nearly everything testable without hardware.

- **Unit, no hardware — the bulk.** `internal/fakekms` provides a KeyManager over
  an in-memory key, with variants that implement `CertificateChainManager`, only
  `CertificateManager`, or neither, covering all three chain-source branches;
  plus one whose signer refuses PSS, proving the test-signature check fires.
  Table tests for public-key mismatch, `path=` without `certificate`, unknown
  scheme, and the expired-leaf warning.
- **Caddyfile adapter.** `caddytest.AssertAdapt` on Caddyfile→JSON. This is what
  catches the value-vs-pointer trap in F4, whose failure mode is a silently
  missing certificate.
- **Manager semantics.** Injected `now` for TTL expiry; a KeyManager that fails
  on the second resolve, for stale-on-error; concurrent `GetCertificate` calls
  asserting singleflight collapses them to one resolve; an SNI-matching table
  with wildcards and IP SANs.
- **Integration: a real TLS 1.3 handshake, no TPM.** A `caddytest` server with
  `load_kms` over a `softkms` key and an on-disk certificate, dialled by a real
  client, asserting the handshake completes and the served chain is ours. This is
  the test that proves the opaque-`crypto.Signer` path works end to end — the
  part most likely to be subtly wrong in a way unit tests would not reveal.
- **TPM simulator, opt-in.** Behind `//go:build tpmsimulator`, wired through the
  `open` seam with `tpm.New(tpm.WithSimulator(sim))` → `tpmkms.NewWithTPM`. Kept
  out of the default `go test ./...` because `go.step.sm/crypto/tpm/simulator`
  needs cgo and `go-tpm-tools`. CI runs it as a separate Linux job.
- **Real hardware.** A manual checklist in `docs/`. Not gated in CI.

## Build and distribution

```
xcaddy build --with github.com/hslatman/caddy-kms
```

Pure Go with the default backend set (D3), so this cross-compiles without cgo.

`go.step.sm/crypto` already ships opt-out build tags — `nopkcs11`, `noyubikey`,
`nomackms`, `noawskms`, `noazurekms` — so if the backend set is widened later,
trimming is a documented `-tags` list rather than a code change.

## Future work

Out of scope now; recorded so the design does not have to change to accommodate
them later.

- Additional backends. Because no module code is backend-specific, this is an
  import line in `backends.go` plus documentation.
- A background-refresh mode for the manager, if lazy TTL (D4) proves awkward in
  practice.
- OCSP stapling interaction. Caddy staples for unmanaged certificates it can
  fetch responses for; whether that behaves well for KMS-sourced chains has not
  been tested and is not claimed to work.
