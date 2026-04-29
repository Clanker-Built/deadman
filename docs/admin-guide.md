# Admin guide

Operator-facing playbook for a running Deadman instance. Assumes
you've completed [quickstart.md](quickstart.md) and have admin rights.

For incident procedures (chain break, key compromise, restore from
backup), see [runbook.md](runbook.md).

## The admin panel

`/ui/admin/` — only visible to users with `is_admin = true`. The first
login matching `DEADMAN_BOOTSTRAP_ADMIN_EMAIL` while no admin exists
auto-promotes; thereafter, additional admins must be flipped via:

```sql
UPDATE users SET is_admin = TRUE WHERE email = 'second@admin';
```

Pages:

| Page | URL | Purpose |
| --- | --- | --- |
| Overview | `/ui/admin/` | Counts: users, policies by state, recent ledger events |
| Users | `/ui/admin/users` | List + drill-down per-user |
| Policies | `/ui/admin/policies` | All policies across all users |
| Ledger | `/ui/admin/ledger` | Filterable audit log + chain-verify button |
| Storage | `/ui/admin/storage` | Primary + backup buckets, drift incidents |
| Vault | `/ui/admin/vault` | Vault unlock state + key custody |
| Backups | `/ui/admin/backups` | Run backup, list past backups |
| Metrics | `/ui/admin/metrics` | Per-route p50/p95/p99, event rates |
| Config | `/ui/admin/config` | SMTP, public base URL, mailer toggle |

## Vault management

The release key is split 2-of-3 across:

1. Operator passphrase 1 (Argon2id-derived)
2. Operator passphrase 2 (Argon2id-derived)
3. Offline recovery share (BIP39-style mnemonic, printed at install)

Two of three reconstruct the key. Day-to-day, the vault is unsealed
at service start when the operator provides the two passphrases via
`/ui/admin/vault/unlock` (or the systemd EnvironmentFile, for
unattended restart — note the trade-off: that file becomes a
single-host secret).

**Sealed state.** Releases pause; check-ins still work. The release
worker logs "vault sealed; deferring release" and retries on the next
tick. Unseal as soon as is reasonable.

**Rotation.** Rotate passphrases via `/ui/admin/vault/rotate`. The
existing release key is unwrapped under the old shares and re-wrapped
under new ones; no key change happens. To rotate the *release key
itself*, follow the runbook procedure — it requires republishing the
public key to all clients and is more involved.

## The audit ledger

Every state transition, login, and admin action writes a row to the
`audit_events` table. Each row contains:

- Sequential `seq`
- `prev_hash` (SHA-256 of the previous row's serialized form)
- `payload_hash` (SHA-256 of this row's payload)
- A server signature (Ed25519 over `prev_hash || payload_hash || seq`)

This chain is the platform's tamper-evident substrate. Verification:

- **In-app:** `/ui/admin/ledger` → **Verify chain integrity**. Should
  print `chain=ok` with the current tip.
- **CLI:** `scripts/publish-chain-tip.sh` writes the current tip
  (signed) to a file you can publish to a static site, git repo, or
  dead-drop. Runs as a daily cron — see the
  [self-hosting.md](self-hosting.md) day-2 hardening section.
- **External pin:** publish the daily tip somewhere out-of-band
  (e.g., commit to a public git repo). After-the-fact verification
  compares the running ledger against the historical tips.

**Boot-time verification.** The control plane re-verifies the chain
on every start. If it fails, the service refuses to start. To
override (incident response only): `DEADMAN_SKIP_AUDIT_VERIFY=1`.
That env var is logged loudly and should never be set in steady state.

## Storage

`/ui/admin/storage` shows live primary + backup buckets and any drift
incidents detected by the verifier worker.

The verifier samples bundle hashes across both buckets on a
configurable cadence. Drift (a bundle present on primary, missing or
corrupt on backup, or vice versa) emits a `storage.drift` audit event
and surfaces in the panel. Drift response is in
[runbook.md](runbook.md).

## Backups

`/ui/admin/backups`:

- **Run backup** — captures `pg_dump` of the Postgres database, hashes
  it, and uploads to the configured backup bucket. Audited.
- **List backups** — paginated. Each row shows status, size, SHA-256.
- **Retention** — configurable; defaults to keep 30 most recent.

Backups encrypt only at the storage layer (server-side encryption, if
the bucket has it on). For a stronger threat model, configure the
bucket with object-lock and encrypt the dump locally before upload —
modify `scripts/backup.sh` accordingly.

**Restore drill.** Run quarterly:

```bash
./scripts/restore-drill.sh /path/to/dump.sql.gz
```

This brings up a temporary Postgres in a sibling container, restores
the dump, runs `audit.Verify` against it, and reports. **It does not
touch your live DB.** Failing this drill is a release-blocker — fix
before you next take a real backup.

## SMTP / mailer

`/ui/admin/config`:

- Host, port, username, from-address, insecure-skip-verify (test
  only).
- **Password** is vault-wrapped: it can only be unsealed when the
  vault is unlocked. If you change it while the vault is sealed, the
  mailer resolver will return errors until unseal.

Test send from `/ui/admin/config` after saving — sends a fixed
template to a recipient of your choice and audits the result.

## Watchdog

A separate-host watchdog is a critical operational layer per the
threat model: a silently-stopped scheduler is the worst failure mode.

Two options ship with the repo:

- **`ops/watchdog-cron/`** — Tor-aware cron + Go verifier. Runs on a
  separate host, uses a Tor SOCKS proxy to reach the .onion, and
  alerts if the chain tip stops advancing or the heartbeat endpoint
  goes silent.
- **`ops/watchdog-worker/`** — Cloudflare Worker for clearnet
  deployments (TLS-fronted, not Tor). Same heartbeat contract.

Set up `ops/watchdog-cron/` per its README. Without a watchdog you
have no out-of-band signal that the platform is alive.

## Day-2 checklist

Run through this within a week of install:

- [ ] Verify `audit.Verify` passes (boot log + admin panel button).
- [ ] Verify backup runs and uploads.
- [ ] Run `restore-drill.sh` end-to-end.
- [ ] Set up the watchdog on a separate host.
- [ ] Set up `publish-chain-tip.sh` as a daily cron with output to
      somewhere you don't control end-to-end (git repo, paste site).
- [ ] Document where the vault passphrases and recovery share are
      stored. **Two operators independently can reconstruct** is the
      goal; one operator + one location is fragile.
- [ ] Test end-to-end release with a dry-run policy.

## Incident triage

`grep` your way through the journal:

```bash
sudo journalctl -u deadman-control --since "1 hour ago" \
  | grep -E "ERROR|FAIL|chain|vault"
```

Common signatures:

| Log fragment | What it means |
| --- | --- |
| `audit chain integrity check failed` | Chain break. Don't restart blindly — see runbook. |
| `vault sealed; deferring release` | Vault is locked. Unseal via admin panel. |
| `storage.drift` | Primary/backup divergence. Investigate before re-syncing. |
| `release worker: bundle not found` | Bundle ciphertext is missing from primary storage. Check backup. |
| `BOOTSTRAP ADMIN promotion fired` | Working as designed; clear `DEADMAN_BOOTSTRAP_ADMIN_EMAIL` from env file. |

For anything you can't classify in 5 minutes, escalate to the
[runbook](runbook.md).
