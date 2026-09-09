# Real-hardware verification checklist

Manual verification against an actual TPM. Not run in CI — the automated suite
covers everything reachable without hardware, and the `tpmsimulator` build tag
covers the `tpmkms` code paths against a simulator.

Work through this once per device model you intend to support, and record the
throughput number from step 8.

## 1. Confirm the device is reachable

```
ls -l /dev/tpmrm0
```

Use the resource manager device (`tpmrm0`), not `tpm0`. Confirm the user Caddy
runs as can read and write it — usually via the `tss` group.

## 2. Create a key

Record the exact storage directory; step 4 depends on it.

```
step-kms-plugin create \
  --kms 'tpmkms:storage-directory=/etc/step/tpm' \
  'tpmkms:name=caddy-tls'
```

Prefer ECDSA P-256. If you must use RSA, create it with a PSS-capable scheme —
an RSASSA-only key cannot serve TLS 1.3, and this module will refuse it at
config load.

## 3. Get a certificate

Issue a certificate for the key from whatever CA you use, then either store the
chain in the TPM:

```
step-kms-plugin certificate --import ... 'tpmkms:name=caddy-tls'
```

or write it to a PEM file and point `certificate` at it. Both are supported;
the file path is the only option for `path=` keys.

## 4. Configure Caddy

```
example.com {
    kms_certificate tpmkms:name=caddy-tls {
        storage_directory /etc/step/tpm
    }
}
```

`storage_directory` **must** match step 2. A mismatch is the single most common
cause of "key not found", which is why the module logs the storage directory it
actually used at startup — check that line first when a key cannot be found.

## 5. Validate

```
caddy validate --config Caddyfile
```

Expect this to open the TPM and perform one test signature. It fails on a
machine without access to the device; that is by design, since validation
happens at config load.

## 6. Confirm no ACME was attempted

Start Caddy and search the log for ACME activity against your names. There
should be none: Caddy skips automatic management for names it already holds a
certificate for.

## 7. Confirm what is actually served

```
openssl s_client -connect example.com:443 -tls1_3 -servername example.com
```

Check the presented chain is the expected one and that the negotiated version is
TLS 1.3. TLS 1.3 specifically, because that is the path an RSASSA-only key would
fail on.

## 8. Measure the handshake ceiling

```
openssl s_time -connect example.com:443 -new -time 30
```

**Record the connections-per-second figure.** Every handshake costs one TPM
signature — open, key load, sign, close — serialized process-wide. This number
is the throughput ceiling for this device, and it is the concrete version of the
warning in the README. Re-run with session resumption (`-reuse`) to see what
resumption buys.

## 9. Rotate with a reload

Replace the certificate externally, run `caddy reload`, and confirm the new
certificate is served. Note the reload cost: one open, key load, sign, close per
configured certificate.

## 10. Rotate without a reload

Only if you use `get_certificate kms`. Replace the certificate externally, wait
for `ttl` to lapse, and confirm the new one is served without a reload.

## 11. Confirm reload safety under load

Run step 8's load generator while issuing `caddy reload`. Handshakes should
continue throughout. The TPM is not held open between signatures, so a reload
does not have to contend with a lingering device handle — this step verifies
that in practice.
