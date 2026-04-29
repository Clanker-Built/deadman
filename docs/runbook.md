# Operational Runbooks

Written for one operator at 2am. Every procedure is idempotent where possible
and explicitly says what NOT to do under stress.

If you self-installed via `scripts/setup-onion.sh`, paths in this document
default to the install layout that script produces:

- Control-plane binary: `/opt/deadman/bin/deadman-control`
- State (vault, signing key): `/var/lib/deadman/`
- Env file: `/etc/deadman/deadman.env`
- Server log: `/var/log/deadman/server.log`
- Tor hidden-service dir: `/var/lib/tor/deadman/`
- Service: `systemctl status|restart|stop deadman-control`
- Stack: `docker compose -f /path/to/repo/ops/docker/docker-compose.yml ...`

If you installed by hand to a different layout, substitute paths.

## 0. Prerequisites

You should know:

- How to SSH into the control-plane host.
- How to run `psql` against Postgres. On the default install:
  ```bash
  docker compose -f ops/docker/docker-compose.yml exec postgres psql -U deadman
  ```
- The pinned Ed25519 service public key, memorized or kept on a second
  device. The admin panel exposes it; the watchdog endpoint also does.
- Where the offline recovery share (share 3) is stored. Not in your
  password manager. Not on this host. Somewhere physical.
- Both vault passphrases — or at least one passphrase + the share-3
  location — held by the actual humans who are supposed to hold them.

If you don't know any of these right now, stop reading and go fix that.

## 0a. Tor onion service (self-host only)

The hidden-service hostname and private key live in
`/var/lib/tor/deadman/`. Whoever has that directory can impersonate your
onion. Back it up encrypted. Loss of `/var/lib/tor/deadman/` means the
.onion address dies — every user has to be told the new one.

Tor itself runs as a separate systemd service:

```bash
systemctl status tor                     # is Tor running
journalctl -u tor -n 100                 # recent Tor logs
cat /var/lib/tor/deadman/hostname        # current onion address
systemctl reload tor                     # re-read torrc.d after edits
```

If `journalctl -u tor` shows hidden-service errors, common causes:

- Permissions on `/var/lib/tor/` got loosened (Tor refuses to use the
  directory if perms are too open). Fix: `chmod 700 /var/lib/tor/deadman`.
- `/etc/tor/torrc` doesn't include `/etc/tor/torrc.d/*.conf`. Add the
  `%include` line and reload.

---

## 1. Scheduler appears stalled (watchdog alerted)

**Symptom**: `deadman-watchdog` pages you with "scheduler stale: last tick Xs ago".

**What it means**: the scheduler goroutine either died, is blocked on a DB query, or the whole control plane is down.

**Triage (≤3 min)**:

```bash
# Is the service process alive?
systemctl status deadman-control  # or `ps aux | grep deadman-control`

# Can it hit DB?
curl -sk https://deadman.example.org/readyz
```

**If `readyz` returns 503**: DB is the problem → jump to §2.
**If `readyz` is 200 but watchdog shows stale ticks**: goroutine is wedged. Capture a profile and restart.

```bash
# Grab a stack dump before restart (invaluable for post-mortem).
curl -sk https://deadman.example.org/debug/pprof/goroutine?debug=2 > /tmp/goroutines.txt  # if enabled
systemctl restart deadman-control
```

**Do NOT**: delete the database, rotate any keys, or re-issue certs. None of those are the fix.

---

## 2. Postgres primary unreachable

**Symptom**: `readyz` → 503 with DB error, control plane logs `store: connect: ...`.

**Managed provider (Neon / Supabase / RDS)**:
1. Check the provider's status page. If they're down: wait, note the time, do nothing.
2. If only your instance is affected, trigger failover per provider's runbook.
3. Update `DEADMAN_DATABASE_URL` if the failover endpoint changed, restart control plane.

**Self-hosted**:
1. `pg_isready` on the primary.
2. If primary is dead and you have a streaming replica, promote it:
   ```bash
   # On the replica:
   pg_ctl promote -D $PGDATA
   ```
3. Update `DEADMAN_DATABASE_URL` to point at the promoted replica.
4. Restart control plane.

**What you lose**: if the primary died mid-write, some releases may be in state `unsealing` / `packaging` / `publishing`. They're idempotent on release_transaction_id, so on restart the release worker resumes from wherever it crashed.

**Do NOT**: start the release worker manually in a mode that skips idempotency. Never add an "at-most-once" knob under stress; partial releases are always recoverable by letting the scheduler advance them.

---

## 3. Primary object storage outage

**Symptom**: watchdog still green (scheduler ticks fine), but `bundle.primary_missing` audit events accumulate.

**What it means**: the backup is doing its job. Release worker's `DualWriter.Get` has already been serving from backup — `release.unseal_source` audit events confirm it.

**Action**:
1. Verify backup reads are succeeding:
   ```sql
   SELECT count(*) FROM audit_events
   WHERE event_type = 'release.unseal_source'
     AND payload->>'source' = 'backup'
     AND occurred_at > now() - interval '1 hour';
   ```
2. Open a ticket with the primary storage provider.
3. Do NOT fail over writes — new uploads still go to both. If the primary write fails during upload, the user sees an error and the bundle is recorded with `backup_ok=true`; no data loss.
4. Once primary recovers, the verifier will detect `primary_missing` and (manually) you can re-upload via:
   ```bash
   # Planned for M5: `deadman-control admin reheal-primary`
   ```
   For now, re-upload affected bundles manually by fetching from backup and PUTting to primary.

---

## 4. Hash drift detected (`bundle.drift` audit events)

**Symptom**: verifier emits `bundle.drift` — primary and backup SHA-256 disagree.

**This is SERIOUS.** It means either bit-rot or tampering.

**Never self-heal.** Do not automatically overwrite one side with the other. The verifier is deliberately hands-off.

**Investigate**:
1. Identify the bundle:
   ```sql
   SELECT payload FROM audit_events WHERE event_type = 'bundle.drift' ORDER BY seq DESC LIMIT 5;
   ```
2. Pull both copies:
   ```bash
   mc cp primary/deadman-primary/bundles/<user>/<bundle>.bin /tmp/p.bin
   mc cp backup/deadman-backup/bundles/<user>/<bundle>.bin /tmp/b.bin
   sha256sum /tmp/p.bin /tmp/b.bin
   ```
3. Compare to `content_bundles.ciphertext_sha256` (the upload-time canonical):
   ```sql
   SELECT encode(ciphertext_sha256, 'hex') FROM content_bundles WHERE id = '<uuid>';
   ```
4. Whichever side matches the canonical is authoritative. Copy that one over the mismatched side, using the object storage admin tool out-of-band — do NOT write a "repair" endpoint.
5. File a post-mortem. Which provider drifted? What other bundles hit them in the same window?

---

## 5. Service signing key rotation

**Rotation is a user-visible event** because `service-signing-key.bin` signs audit entries and the watchdog. Changing it breaks any verifier pinning the old pubkey.

**Plan a window**:
1. Announce rotation in audit log:
   ```sql
   -- hand-write a ledger append via the appendTx path is not available out-of-band;
   -- instead, emit via a one-shot CLI (planned). For now, record intent in the admin
   -- changelog and in a signed note using the OLD key just before rotation.
   ```
2. Stop the control plane.
3. `mv service-signing-key.bin service-signing-key.bin.rotated-$(date +%s)`.
4. Start the control plane. It generates a new key on first run.
5. Read the new pubkey: `curl https://deadman/watchdog | jq -r .service_pubkey`.
6. Update the watchdog worker's `SERVICE_PUBKEY_B64URL` and redeploy.
7. Update any out-of-band subscribers of the old key (journalists verifying past releases, etc.) with a signed announcement using BOTH keys.

**Do NOT**: rotate the signing key and the release key in the same maintenance window. One at a time. Rotation is the highest-risk operation.

---

## 6. Release key rotation

**The release key (RSA-3072) decrypts all bundle DEKs.** Rotating it means:
- Old bundles can't be decrypted by the new key (DEKs are wrapped against the OLD pubkey).
- Users must re-upload every bundle against the new pubkey.

**This is not a routine operation.** Only do it if you believe the release private key was compromised.

If the key is compromised:
1. Set the policy state of every affected user to `suspended` to prevent any trigger from firing with the compromised key.
2. Generate new vault (see §6a).
3. Notify every user to log in, re-upload bundles, and re-arm.
4. After a safe window, delete the old key material and old vault file.

### 6a. Threshold vault setup and daily operation

The release private key is stored as a Shamir 2-of-3 split in a JSON
vault file (default `./release-vault.json`, mode 0600). Three shares:

- **Share 1** — wrapped by Argon2id-derived KEK from **passphrase A**.
- **Share 2** — wrapped by Argon2id-derived KEK from **passphrase B**.
- **Share 3** — printed ONCE at vault generation; never stored server-side.
  Write it down on paper; keep in a safe you control.

**Pair the two passphrases with two different people / two different
trust domains**: one per human custodian, or one on disk + one on a
hardware-backed keyring. Do not memorize both yourself — that defeats
the split.

#### First-time vault generation

```bash
export DEADMAN_VAULT_PASSPHRASE_A='…long random string, custodian A…'
export DEADMAN_VAULT_PASSPHRASE_B='…long random string, custodian B…'
make dev-run  # (or whatever your launch command is)
```

On first run, the server:

1. Creates `release-vault.json`.
2. Prints share 3 to stderr. **Record it immediately** — it's shown exactly once.
3. Auto-unlocks using the env passphrases and proceeds normally.

After recording share 3, you can keep the passphrases in env for
unattended restarts, or clear them and rely on interactive unlock
(an admin `/admin/unlock` HTTP endpoint is planned; today the only
unlock path is env vars at startup).

#### Normal restart

```bash
export DEADMAN_VAULT_PASSPHRASE_A='…'
export DEADMAN_VAULT_PASSPHRASE_B='…'
# Start server — it reads the existing vault and unlocks.
```

If the server starts without the passphrases, it runs **locked**:
uploads and non-release endpoints still work, but any triggered policy
stalls in `unsealing` state until you restart with the passphrases.
This is desirable — a silent key-release after a restart would defeat
the point of requiring unlock.

#### Recovering from a lost passphrase

If passphrase B is lost, you need **passphrase A + share 3** (the
offline recovery share). The admin recovery path is:

```go
// Programmatic only today (via a small CLI being built):
locker.UnlockWithRecovery(vf, "passphrase A", share3Mnemonic, 1)
```

A CLI subcommand `deadman-control vault recover` will ship with M5+1.
Until then, recovery requires a manual Go program; note this in your
key-custody plan.

#### What the threshold split buys you

- Filesystem read alone gives only wrapped shares; no plaintext key.
- Knowing ONE passphrase alone still leaves attacker one short.
- Losing ONE custodian's memory is recoverable via share 3.

What it does NOT defend against:
- The running process after unlock. Operator-observable restarts +
  the external watchdog are the only mitigation.
- Both passphrases known to the same person. The split is only as
  strong as the trust separation you enforce in custody.

### 6b. Migration from legacy single-key deployment

If you were running with `release-key.pem` (the pre-M5 default), migrate:

1. **Do not delete `release-key.pem` yet.** Keep it around until
   migration completes and you've verified release works.
2. Start the server with `DEADMAN_LEGACY_SINGLE_KEY=true` one more
   time and note all currently-armed policies; warn users.
3. Stop the server.
4. Write a one-shot migration program (M5+1 will provide a subcommand):
   - Load the existing `release-key.pem`.
   - Pass the parsed `*rsa.PrivateKey` directly into a new `Generate`
     variant that uses an externally-supplied key instead of
     generating a fresh one.
   - Persist the vault.
   - Store the public key unchanged (bundles already reference it).
5. Remove `DEADMAN_LEGACY_SINGLE_KEY`. Restart with vault passphrases.
6. Verify releases unseal by triggering a test policy.
7. Securely delete `release-key.pem` (`shred -u` on Linux).

---

## 7. Emergency: I think the system is about to release something it shouldn't

**Suspend first, investigate second.**

```sql
-- Suspend ALL armed policies for a user:
UPDATE policies SET state = 'suspended'
 WHERE user_id = '<uuid>' AND state IN ('healthy','warning','grace','hold','triggered');
```

Note: this bypasses the state machine's own signing path, so it will create a gap in the hash-chained audit trail for the affected policies. That is INTENTIONAL evidence of an operator intervention — do not try to cover it up.

Then figure out what's going on. Suspension is reversible via `/ui/policies/:id/resume` (or an equivalent SQL update) once you've determined no data was lost.

**Do NOT**: delete rows from `policies` or `release_transactions`. Ever. The audit trail is more important than removing embarrassing entries.

---

## 8. Restoring from backup

DB + object storage are both backed up. A full DR restore looks like:

```bash
# 1. Stand up a fresh Postgres and restore the latest PITR snapshot.
pg_restore -d deadman backup.dump

# 2. Ensure the bucket replica is reachable. If the primary is gone too,
#    swap roles in DEADMAN_S3_* env so the backup becomes primary.

# 3. Bring up the control plane pointed at the restored DB + remaining bucket.

# 4. Verify: run one forced trigger on a test policy and watch it release
#    end-to-end. If it works, you're back online.
```

**Recovery drill cadence**: run this from a cold snapshot every quarter. Document the time-to-recover in your compliance log; adjust SLA promises accordingly.

---

## 9. What to tell users after an incident

- If no user data was lost: short postmortem linked to the audit-event timestamp.
- If user data was potentially exposed (release-key compromise, DB leak): **immediate** notification to every affected user via every channel you have for them, with a timestamp, what was exposed, what you did about it, and what they should do.
- Never minimize. Trust is the product.

---

## 10. Self-host checklist (Tor install via setup-onion.sh)

When something feels off on a self-host, run through these in order:

```bash
# Service alive?
systemctl status deadman-control
journalctl -u deadman-control -n 100

# Server log (where share-3 was printed at first boot)
sudo tail -n 200 /var/log/deadman/server.log

# Tor hidden service alive?
systemctl status tor
cat /var/lib/tor/deadman/hostname
journalctl -u tor -n 50

# DB up?
docker compose -f ops/docker/docker-compose.yml ps
docker compose -f ops/docker/docker-compose.yml exec postgres pg_isready -U deadman

# Storage up?
docker compose -f ops/docker/docker-compose.yml exec minio mc ready local
docker compose -f ops/docker/docker-compose.yml exec minio_backup mc ready local

# Vault state?
sudo grep -E "vault (unlocked|generated|locked)" /var/log/deadman/server.log | tail
```

Common self-host issues:

- **Onion unreachable from Tor Browser** but local probe works
  (`curl http://127.0.0.1:8080/healthz` returns ok): Tor still
  publishing the descriptor. New onions take 1-3 min to appear in the
  network. Wait, then retry.
- **WebAuthn fails immediately** on the .onion: confirm
  `DEADMAN_RP_ID` in `/etc/deadman/deadman.env` is the bare onion
  hostname (no `http://`, no trailing `/`, no port). Then
  `systemctl restart deadman-control`.
- **Service fails to start with "vault is locked"**: env file lost the
  passphrases (you removed them on purpose, or accidentally). Either
  put them back, or unlock via `/ui/admin/vault` after starting in the
  locked state.
- **Disk filling up**: docker volumes at `/var/lib/docker/volumes/`,
  bundle uploads in MinIO, server log at `/var/log/deadman/server.log`,
  Postgres WAL. Rotate the server log via systemd/journalctl, prune
  old MinIO objects from old test bundles, or move volumes to a larger
  disk.

## 11. What NOT to do under stress (self-host edition)

- **Never `rm -rf /var/lib/tor/deadman/`** to "reset" Tor. That destroys
  the onion address and forces every user to be re-told the new one
  out-of-band. Once that trust hop happens, an attacker can phish a new
  "we moved" announcement.
- **Never `docker compose down -v`** to "restart fresh". The `-v` deletes
  the Postgres and MinIO volumes — that is your DB and your bundles.
- **Never edit the `audit_events` table directly.** A trigger blocks
  UPDATE/DELETE; if you find a way around it, you've broken the chain
  and the only thing the chain was *for* was detecting that.
- **Never publish the offline recovery share over any channel that isn't
  paper to a safe.** If you typed it into a chat to a custodian, it's
  compromised — re-generate the vault.
