# Cryptographic Specification

This document is the single source of truth for every cryptographic
construction Deadman uses. If you're auditing the code, start here.
If you're modifying any of this, read [`CONTRIBUTING.md`](../CONTRIBUTING.md)
on cryptographic-change procedure first.

## 1. Primitive choices

| Use | Algorithm | Library | Why |
|---|---|---|---|
| Bundle DEK encryption | AES-256-GCM | `crypto/cipher` | WebCrypto-compatible (browser-side encryption); FIPS-approved AEAD; nonce-misuse cost is high but not catastrophic. |
| DEK wrap | RSA-OAEP-SHA256 | `crypto/rsa` | WebCrypto support is uniform across browsers; X25519 is patchier. |
| Release keypair | RSA-3072 | `crypto/rsa` | NIST SP 800-57 Part 1 Rev. 5: 3072-bit RSA → ≥128-bit security strength. |
| Service signing | Ed25519 | `crypto/ed25519` | Small signatures; deterministic; standard library. |
| Audit-event hashing | SHA-256 | `crypto/sha256` | Standard. |
| Threshold split | Shamir 2-of-3 over GF(2^8) | `github.com/corvus-ch/shamir` | Audited, small dependency, byte-aligned shares. |
| Passphrase KEK | Argon2id | `golang.org/x/crypto/argon2` | Memory-hard; mainline OWASP / IETF RFC 9106 recommendation. |
| Server-secret wrap | RSA-OAEP-SHA256 + AES-256-GCM | this repo | Same scheme as bundle DEK with a domain-separated AAD. |
| Session token | 32 random bytes (b64url) | `crypto/rand` | High entropy; SHA-256 of token stored, never the token itself. |
| CSRF token | 32 random bytes (b64url) | pgcrypto `gen_random_bytes` | Per-session, persisted to DB; cleared on session revocation. |

## 2. Key hierarchy

```
                  Service signing key (Ed25519)
                   │
                   └─ Signs audit events (per-row)
                   └─ Signs watchdog heartbeat
                   └─ Signs release manifests

                  Release keypair (RSA-3072)
                   │
                   ├─ Public key
                   │    │
                   │    ├─ Wraps bundle DEKs at upload time
                   │    ├─ Wraps SMTP password (admin)
                   │    └─ Wraps future destination secrets
                   │
                   └─ Private key
                        │
                        └─ Lives in PROCESS MEMORY ONLY when unsealed.
                           Reconstructed via Shamir 2-of-3:
                              - share 1 → Argon2id KEK from passphrase A
                              - share 2 → Argon2id KEK from passphrase B
                              - share 3 → offline recovery (not stored)
```

There is no third "data-encryption" key. Bundle DEKs are per-bundle
random; that randomness *is* the per-payload key. The release private
key is the only long-lived secret.

## 3. Bundle wrap (browser → server)

Per-bundle:

```
DEK     = random 256 bits
nonce   = random 96 bits  (AES-GCM standard)
aad_v1  = "deadman/release-wrap/v1"

ciphertext  = nonce || AES-256-GCM(DEK, nonce, plaintext, aad_v1)
wrapped_key = RSA-OAEP-SHA256(release_pub, DEK, label=aad_v1)
```

Stored shapes:

- `content_bundles.wrapped_bundle_key` ← `wrapped_key`
- `content_bundles.wrap_scheme`        ← `"rsa-oaep-sha256.aes-gcm.v1"`
- `content_bundles.ciphertext_sha256`  ← SHA-256(ciphertext) (binding identifier)
- Object store object body              ← `ciphertext`
- Object store object key               ← derived from `(user_id, bundle_id)`

Browser performs all of this with WebCrypto:

1. `crypto.subtle.importKey('jwk', release_jwk, ...)`
2. `crypto.subtle.generateKey('AES-GCM', 256, ...)`
3. `crypto.subtle.encrypt('AES-GCM', dek, plaintext, aad)`
4. `crypto.subtle.encrypt('RSA-OAEP', release_pub, dek_raw)`

The Go reference encryption (used by tests) lives in
`internal/crypto/release.go::EncryptBundleForRelease`. Decrypt is
`DecryptBundleForRelease`.

## 4. Threshold vault

The release private key is split via Shamir 2-of-3 over
GF(2^8) using `corvus-ch/shamir`. Each share is the raw byte slice the
library returns, prefixed with a 1-byte share ID (the library uses the
last byte as ID; we materialize it as the first byte of the persisted
form so we can transmit it without ambiguity).

Share wrapping:

```
salt_A   = random 16 bytes
salt_B   = random 16 bytes

KEK_A    = Argon2id(passphrase_A, salt_A, t=3, m=64MB, p=1, len=32)
KEK_B    = Argon2id(passphrase_B, salt_B, t=3, m=64MB, p=1, len=32)

share1_wrapped = AES-256-GCM(KEK_A, nonce_A, share1_bytes, aad="deadman/vault/share1")
share2_wrapped = AES-256-GCM(KEK_B, nonce_B, share2_bytes, aad="deadman/vault/share2")
share3         = NOT STORED. Printed once at vault generation.
share3_fp      = SHA-256(share3_bytes) — stored, used to verify
                 transcription accuracy at recovery time.
```

The vault file is a JSON document containing:

```json
{
  "version":            1,
  "release_pub_jwk":    { "kty": "RSA", "alg": "RSA-OAEP-256", "n": "...", "e": "..." },
  "share1": {
    "salt":             "<b64url 16 bytes>",
    "nonce":            "<b64url 12 bytes>",
    "ciphertext":       "<b64url variable>",
    "argon2": { "time": 3, "memory": 65536, "threads": 1 }
  },
  "share2": { ... same shape, different salt/nonce/cipher ... },
  "share3_fingerprint": "<b64url 32 bytes>"
}
```

Persisted to `release-vault.json` mode 0600. Loss of the file destroys
the deployment's ability to release any existing bundle (DEKs cannot
be unwrapped without the release private key).

### Recovery share encoding

Share 3 is rendered for the operator as **lowercase hex with `-`
separators every 4 bytes**:

```
aabbccdd-eeff0011-2233...
```

This is lossless and easy to transcribe by hand. We considered BIP39
word lists but BIP39 mnemonic encoding requires 11-bit-aligned entropy
and our Shamir shares are arbitrary byte length; mapping to BIP39 would
require padding that complicates round-trips. Hex with dashes is
sufficient.

### Unlock paths

Two unlock paths produce the in-memory release private key:

1. **Both passphrases:** unwrap share1 with `KEK_A`, unwrap share2 with
   `KEK_B`, combine via Shamir.
2. **One passphrase + share3:** unwrap whichever passphrase share is
   available, transcribe share3 from paper, verify SHA-256 matches
   `share3_fingerprint`, combine via Shamir.

`UnlockWithPassphrases` and `UnlockWithRecovery` in
`internal/keyvault/keyvault.go` are the entry points.

## 5. Server-secret wrap

Used by:

- SMTP password storage (`server_settings.smtp_password_wrapped`)
- Future destination secret storage (`destinations.secrets_wrapped`)

Wire format (`internal/crypto/server_secret.go::WrapServerSecret`):

```
[1]  version = 0x01
[2]  big-endian length of wrapped_key (max 65535)
[N]  wrapped_key            = RSA-OAEP-SHA256(release_pub, DEK,
                                              label="deadman/server-secret-wrap/v1")
[12] nonce                  = random
[*]  ciphertext             = AES-256-GCM(DEK, nonce, plaintext,
                                          aad="deadman/server-secret-wrap/v1")
```

The AAD is distinct from the bundle wrap AAD so a wrapped server
secret cannot be substituted into the bundle-unseal path.

Decryption requires the unsealed release private key — that is, the
threshold vault must be unlocked. A DB leak alone reveals nothing.

## 6. Audit ledger

Every audit event is hash-chained and Ed25519-signed.

### Canonical serialization

```go
type canonicalEvent struct {
    ID          uuid.UUID
    OccurredAt  time.Time      // UTC, truncated to microseconds
    ActorKind   string
    ActorID     *uuid.UUID
    EventType   string
    SubjectKind string
    SubjectID   *uuid.UUID
    Payload     json.RawMessage
    PrevHash    []byte
}
```

Marshalled with Go's `encoding/json` in struct-field order. Time is
forced to UTC with microsecond truncation so the post-Postgres-roundtrip
value hashes identically.

### Per-row computation

```
prev_hash    = previous row's payload_hash, or 32 zero bytes if first
canon        = canonical JSON of the event
payload_hash = SHA-256(canon)
sig_body     = prev_hash || payload_hash       (64 bytes)
service_sig  = Ed25519.Sign(service_priv, sig_body)
```

All four (`prev_hash`, `payload_hash`, `service_signature`, `payload`)
persist to the row. The DB has an `audit_events_no_update` trigger
that raises on UPDATE/DELETE — the table is conceptually append-only
even from superuser.

### Verification

`internal/audit/audit.go::Verify` walks the chain in `seq` order:

1. Confirms `prev_hash` matches the previous row's `payload_hash`
   (zero bytes for `seq = 1`).
2. Recomputes `canon` from the row's stored fields and verifies
   `SHA-256(canon) == payload_hash`.
3. Verifies `Ed25519.Verify(service_pub, prev_hash || payload_hash,
   service_signature)`.

Any failure stops the scan and returns the seq number of the break.

The control plane runs `audit.Verify` at every boot; mismatch is
fatal. Override with `DEADMAN_SKIP_AUDIT_VERIFY=1` only if you accept
the risk.

The admin panel exposes a button at `/ui/admin/ledger` that runs the
same verification on demand and shows the result.

### External pinning

`scripts/publish-chain-tip.sh` emits a JSON object containing the
latest row's `payload_hash`, `prev_hash`, signature, and metadata.
Operators are expected to publish this daily to a public, timestamped
location (git commit, ntfy.sh, IPFS, anything). An external verifier
who pins the value at time T1 and the latest value at time T2 can
detect any history rewrite between T1 and T2 — the chain has a unique
tip per write history.

## 7. Session tokens and CSRF

### Session

```
token        = 32 random bytes  (crypto/rand)
cookie value = base64.RawURLEncoding(token)
db column    = sessions.token_hash = SHA-256(token)
```

Only the hash lives server-side. Attribution to a session requires
presenting the original 32-byte token. Cookie is `HttpOnly`,
`SameSite=Lax`, `Secure` only when TLS is in use (false on Tor
onion HTTP).

### CSRF

Per-session 32-byte CSRF token, generated server-side at
`CreateSession` time via `gen_random_bytes(32)` (pgcrypto). Rendered
in every form as a hidden `csrf_token` field, b64url-encoded.

`csrfMiddleware` in `internal/httpapi/csrf_mw.go` enforces:

- Skips: `GET`, `HEAD`, `OPTIONS`; paths not starting with `/ui/`;
  requests without a session cookie (handler will 401 / redirect
  itself).
- Otherwise: constant-time compare of submitted form value (or
  `X-CSRF-Token` header) against `base64url(session.csrf_token)`.
  Mismatch → 403, no leak of which side was wrong.

Step-up reauth rotates the session token (and therefore implicitly
the CSRF token).

## 8. WebAuthn / passkey

We use `github.com/go-webauthn/webauthn`. RP config:

- `RPID` = bare onion hostname (or clearnet domain) at runtime
- `RPOrigins` = the `http://` (onion) or `https://` (clearnet) origin
- Display name configurable

Stored credential fields (`webauthn_credentials`):

- `id`              — credential ID bytes
- `user_id`         — FK to users
- `public_key`      — COSE-encoded public key
- `sign_count`      — replay counter
- `transports`      — declared by the authenticator
- `aaguid`          — authenticator model identifier
- `backup_eligible` — flag from authenticator
- `backup_state`    — flag from authenticator (mutable; updated on
                      every assertion to allow legitimate backup-state
                      transitions during sync)
- `created_at`

Replay protection: `sign_count` strictly increasing per credential.
Origin binding: `RPOrigins` is verified by the library against the
collected client data.

## 9. Watchdog

Heartbeat shape (`/watchdog`):

```json
{
  "service_pubkey":       "<b64url Ed25519 pub key>",
  "last_scheduler_tick":  "<RFC3339>",
  "now":                  "<RFC3339>",
  "signature":            "<b64url>"
}
```

Signature canonical input: `"tick=" + last_scheduler_tick + "|now=" + now`.

External verifier (`ops/watchdog-cron/verify-watchdog`) checks:

1. Server-reported `service_pubkey` matches the locally-pinned key.
2. `Ed25519.Verify(pinned_pub, sig_body, signature)`.
3. `now - last_scheduler_tick <= max-stale-seconds` (default 300).

A stuck scheduler is detectable in 5 min ± the watchdog's polling
period.

## 10. Defaults summary

| Knob | Default |
|---|---|
| Argon2id parameters | t=3, m=64 MiB, p=1, output 32 bytes |
| Scheduler tick | 30 s |
| Session TTL | 24 h |
| Step-up window | 5 min |
| Watchdog cron | 5 min |
| Watchdog staleness threshold | 300 s |
| Backup retention | 14 most-recent successful |
| RSA modulus | 3072 bits |
| Bundle AEAD | AES-256-GCM |
| Audit hash | SHA-256 |
| Service signature | Ed25519 |
| CSRF token length | 32 bytes |
| Session token length | 32 bytes |
| Recovery share encoding | hex with `-` every 4 bytes |

Any operator change to these (other than backup retention) should be
recorded in their ops journal — they affect the threat model.

## 11. What is NOT included

- **Forward secrecy on bundle uploads.** The release public key wraps
  every DEK, so compromise of the release private key reads every
  past upload. This is intentional: the architecture is built around
  controlled-disclosure of *past* uploads on a deadman trigger, which
  forward secrecy would defeat. Mitigation: threshold-split the key.
- **Per-recipient encryption.** Email and webhook destinations
  receive material the platform decrypts at trigger time. The platform
  does not encrypt to the recipient's own public key. Operators with
  high-stakes recipients should run a wrapper webhook destination that
  re-encrypts to recipient-specific keys.
- **Anonymous credentials / blind tokens.** Users authenticate as
  themselves; the platform learns who they are. Tor hosting hides
  *network* identity from the platform, but the platform still has
  email, passkey AAGUID, and usage timing.
- **Post-quantum primitives.** RSA-3072 + Ed25519 are not PQ-safe.
  Migration to a hybrid scheme (e.g., RSA + ML-KEM) is a future
  task. Today, the practical risk is bounded by the 5-15-year
  expected lifetime of stored ciphertext under retroactive PQ
  decryption assumptions.
