# Threat Model

Living document. For each in-scope threat (originally from SPECS.md §6),
track what the current build does about it. A threat with no mitigation
at this point of the build is a flag for self-hosters to either accept
or compensate for at deployment time.

## Posture, in one paragraph

The implemented build covers the user-facing crypto, ledger, scheduler,
and release-pipeline threats. It does **not** by itself mitigate the
operator-facing threats — host compromise, legal compulsion, hostile
hosting providers, deanonymization of a Tor-hosted instance — and at
solo-scale it cannot. The shipping posture is "self-host on a host you
control, in a jurisdiction you understand, for a user base you trust";
threats that depend on cloud diversity, multi-party custody, or formal
legal infrastructure get marked `accepted` rather than pretended-away.

## Conventions

- **Status:**
  - `covered` — mechanism is implemented and tested in this build
  - `partial` — implemented but with caveats called out in the row
  - `accepted` — not technically mitigated; the operator/self-host model
    is expected to handle it (or accept the residual risk)
  - `planned` — left unimplemented for a future phase

## In-scope threats

| # | Threat | Mitigation | Status |
|---|---|---|---|
| 1 | Password theft | Passkeys (WebAuthn) only; no passwords or SMS. | covered |
| 2 | Phishing against user credentials | WebAuthn assertions are origin-bound; forged login pages cannot reuse the assertion. | covered |
| 3 | SIM swap against SMS-based auth | SMS auth never implemented; no fallback path. | covered |
| 4 | Cloud credential compromise (single bucket) | Bundle ciphertext is replicated to a configurable secondary bucket; release worker reads from backup if primary fails; verifier flags drift between the two without auto-healing. | covered |
| 5 | Insider abuse by the operator | Zero-knowledge: bundles are wrapped with the release public key, decrypted only after a policy triggers AND the threshold vault is unlocked. Audit ledger is hash-chained and Ed25519-signed, with an externally-pinned service public key for offline verification. The operator cannot read user material *and* cannot silently rewrite history. | covered |
| 6 | Theft of a user device | Browser-only build today. WebAuthn passkeys live in the user's authenticator (hardware token, OS keyring, or sync-fabric like Bitwarden); operator never sees the private key. Loss of the device requires the user's recovery flow (re-register passkey via the email channel they own). | partial — depends on the user's authenticator's own device-loss UX |
| 7 | Malware on a user device | Operator cannot tell. Per-action passkey assertions limit blast radius on logged-in browsers; the platform itself does not detect or remediate compromised endpoints. | accepted |
| 8 | One-cloud outage | Primary + backup buckets; release worker falls back; admin dashboard exposes drift and primary-missing counts. | covered |
| 9 | Unauthorized policy modification | Every state transition is signed by the user (passkey-asserted session), epoch-CAS optimistic-concurrency in the policy state table, and ledgered. | covered |
| 10 | Premature release | Scheduler uses server-canonical time only. No client-clock trust anywhere. Force-trigger is a dev-only handler gated on `cfg.DevMode`. | covered |
| 11 | Silent failure to release | Internal: the scheduler's `OnTick` writes to the watchdog. External: `ops/watchdog-worker/` is a Cloudflare Worker cron that hits the watchdog endpoint, verifies the Ed25519-signed heartbeat, and pages the operator if `last_tick` goes stale. Optional but strongly recommended. | partial — only takes effect if the operator deploys the watchdog |
| 12 | Rollback of policy state | `policy_states.epoch` enforces atomic-CAS updates; ledger is hash-chained so a rollback would manifest as a chain break that the admin "Verify chain" button surfaces. | covered |
| 13 | Theft of destination tokens / SMTP password | SMTP password is wrapped with the release public key (RSA-OAEP + AES-GCM). The DB row alone reveals nothing; an attacker would also need the unsealed release private key. Webhook tokens stored in `destinations.config` are *not* wrapped today — that is a planned enhancement. | partial — webhook tokens not yet wrapped |
| 14 | Time manipulation against the host | Single canonical scheduler tick. With the external watchdog deployed, a manipulated host clock manifests as missed ticks against an independent prober. Without the watchdog, a fully-compromised host that lies about time is undetected from outside. | partial |
| 15 | Queue poisoning | Release transactions are idempotent on `(policy_id, epoch)`; the scheduler can be safely killed and restarted mid-release. | covered |
| 16 | Unauthorized deletion of stored content | Bundles soft-delete only (`deleted_at`); audit ledger has an append-only DB trigger. Object-store side: depends on bucket configuration (versioning, MFA-delete) — covered when the operator configures the buckets that way; default MinIO does not. | partial |
| 17 | Operator forced to hand over keys | Threshold split: the unsealed release private key only exists in process memory after the operator types both passphrases (or one passphrase + the offline recovery share). Cold disk + unlocked process is needed to obtain the key; a court order can compel the operator to type the passphrases, which mitigates only against operators willing and able to refuse. | partial — see [operator-risks.md](operator-risks.md) |
| 18 | Operator deanonymized while hosting via Tor | The platform supports onion-only hosting, but operational mistakes (clearnet leaks, payment trails, SSH from home IPs) are outside the platform's ability to prevent. Tor itself does not protect against a determined state-level adversary. | accepted |

## Partial-scope threats

| # | Threat | Posture |
|---|---|---|
| A | Full compromise of all user devices | Accepted. No trusted-contact recovery in this build. |
| B | User coercion | Mitigated only by user-chosen interval length and the platform's minimum 24 h grace + 1 h publication delay. No anti-coercion delay-extensions. |
| C | Compromise of all clouds and all key custodians | Beyond solo-scale defense. Threshold split + cloud diversity reduce probability; do not eliminate. |
| D | Government seizure of the host | Self-host model passes this to the operator. The threshold vault makes "seize the host while it's running" the only successful attack path (cold disk yields wrapped shares only). |
| E | Abuse by users uploading material the operator would refuse to host knowingly | Zero-knowledge prevents pre-screening. Mitigation is operator-side: clear use-case scoping, abuse-response policy, willingness to suspend policies via the admin panel. See [operator-risks.md](operator-risks.md). |

## Out-of-scope

- User intentionally misconfiguring release content
- User voluntarily giving away their credentials or recovery share
- Third-party censorship of published material *after* it has been
  released to destinations
- Recipients refusing to act on a release they've received
- Adversary modifying the published landing page on a third-party host
  the operator does not control (use webhooks to mirrors you do
  control instead)

## Review cadence

Self-hosters should re-walk this document:

- At install time, when deciding whether to host for others
- When adding new destination kinds (each new destination type opens new
  threats around its credentials and recipients)
- After any incident that surfaces a row currently marked `partial` or
  `accepted` as a real cost
- At least annually
