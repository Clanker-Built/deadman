# Self-Hosting Deadman over Tor

This is the long version of `scripts/setup-onion.sh`. Read it before you run
the script if you want to know what it does, and use it as a reference when
something goes wrong or you want to vary from the default install.

The default install is **onion-only, single-host, Ubuntu/Debian**:

- One Linux box that you control.
- Postgres and MinIO in Docker on that box.
- The Go control plane built from this repo and run as a systemd service.
- Tor on the host providing a v3 hidden service that maps the onion's
  port 80 to the control plane on `127.0.0.1:8080`.
- No clearnet listener. No TLS. (The onion provides the secure channel.)

There is no managed alternative; if you want Deadman, you self-host.

---

## Prerequisites

The setup script is a one-shot installer. The only things you need
yourself are:

| Requirement | Why | How to check |
| --- | --- | --- |
| Ubuntu 24.04 / 26.04 LTS (or Debian 12) | The script's apt-based install path | `cat /etc/os-release` |
| A user with sudo access | The script auto-elevates; you'll be prompted once for your password | `sudo -v` |
| Outbound internet | Pulls apt packages, the Go tarball, and the goose migration tool | `curl -fsSL https://go.dev` |
| ~2 GB free disk | DB + bundles + logs grow over time | `df -h /var` |

The script installs Docker, Go 1.25, Tor, ufw, openssl, lsof, jq,
gnupg, and curl/ca-certificates if any of them are missing. If you
already have a recent Docker or Go install, the script detects and
keeps it.

If you'll have any real volume of bundles, plan for the disk to grow
with the size of users' uploaded ciphertext.

---

## What the script does

The order matters; if you're doing this by hand, follow it.

1. **Sanity checks** — root, OS, prereq tools.
2. **Prompts** for admin email, vault passphrases A and B (or generates them
   for you), backup retention, optional SMTP.
3. **Creates** the `deadman` system user and `/var/lib/deadman`,
   `/etc/deadman`, `/var/log/deadman`, `/opt/deadman`.
4. **Builds** `deadman-control` from `control/cmd/server` into
   `/opt/deadman/bin/deadman-control`.
5. **Brings up** the docker-compose stack (Postgres + 2× MinIO).
6. **Runs** DB migrations via goose.
7. **Installs** `/etc/tor/torrc.d/deadman.conf`, reloads Tor, reads back the
   `.onion` hostname.
8. **Writes** `/etc/deadman/deadman.env` (mode 0600, owned by `deadman`).
9. **Installs** and starts `/etc/systemd/system/deadman-control.service`.
10. **Captures** the offline recovery share (printed once on first vault
    generation) from the server log.
11. **Prints** the final report.

---

## Running the script

```bash
git clone <repo> deadman
cd deadman
./scripts/setup-onion.sh
```

(The script auto-elevates with sudo. You can also run `sudo
./scripts/setup-onion.sh` directly if you prefer.)

You'll be asked for:

- **Bootstrap admin email.** The first user who logs in with this email is
  auto-promoted to admin. You can use it once and then leave the field
  blank in steady-state by editing `/etc/deadman/deadman.env`.
- **Vault passphrases A and B.** Two of three Shamir shares are wrapped
  with these (Argon2id-derived KEKs). The third share is offline-only and
  is printed at the end. Choose two strong, *different* passphrases.
- **Backup retention.** Default 14: keep the most-recent 14 successful
  pg_dump backups in object storage; older ones get GC'd.
- **SMTP** (optional). Skip and configure it later from the admin panel.

At the end, it prints your onion URL and the offline recovery share.

> **Write the recovery share on paper. Now. Once.**
>
> The server prints it exactly one time. Losing it means losing the
> ability to recover from a forgotten passphrase — and at that point your
> only options are forced re-upload by every user (key rotation; see
> Runbook §6) or accepting that triggered releases will fail.

---

## Verifying the install in Tor Browser

Tor Browser is the canonical client. Test there before you trust the
install for anything real. Quirks worth knowing:

- **Auth path: passphrase + TOTP.** WebAuthn-on-Tor is unworkable in
  practice (Chromium browsers refuse it on plain-HTTP `.onion`; Tor
  Browser disables `dom.webauthn.enabled` by default and lacks
  caBLE/QR cross-device transport). The platform uses Argon2id +
  RFC 6238 TOTP + 10 single-use recovery codes as its primary login.
  Works in any browser, no extensions required. WebAuthn is preserved
  in the codebase as opt-in for users with a hardware key on a
  TLS-fronted deployment.
- **Security level slider.** Tor Browser's "Standard" and "Safer"
  levels both work; the UI is server-rendered and uses no JS for the
  auth flow itself. "Safest" disables JS globally and the few
  enhancement scripts (countdown timer, etc.) won't run, but auth and
  navigation still function.
- **NoScript** ships with Tor Browser. The platform serves no
  third-party origins, no inline scripts, no eval. Strict CSP with
  per-request nonces means your site should "just work" with NoScript
  in default-allow-first-party mode.
- **TOTP authenticator app.** Aegis (Android) and Raivo (iOS) are
  good privacy-respecting choices. KeePassXC, 1Password, Bitwarden,
  Authy, and Google Authenticator all also work — anything that
  speaks RFC 6238 with HMAC-SHA1 / 30s / 6 digits. The setup page
  shows a manual setup key (no QR — keeps the CSP strict and avoids
  Tor Browser image-rendering quirks).
- **Cookies.** The session cookie is `HttpOnly` and `SameSite=Lax`.
  The `Secure` flag is set only when the request arrived over TLS,
  which it never does on a Tor onion. That's correct: setting
  `Secure=true` on an HTTP origin would prevent the browser from
  storing the cookie at all.

A complete test pass:

1. Open `http://your-onion.onion` in Tor Browser. It should redirect
   to `/ui/` and render the home page.
2. Click **Create account** → enter the bootstrap admin email,
   choose a 12+ char passphrase, accept the six acknowledgments. The
   flow lands on the TOTP setup page.
3. Open your authenticator app, choose "manual entry," enter the
   account name (your email), the setup key shown on the page, and
   pick TOTP / SHA-1 / 6 digits / 30 seconds. Save the 10 recovery
   codes somewhere offline (the page shows them once).
4. Enter the current 6-digit code from your authenticator. The flow
   ends on the dashboard.
5. **Log out**, then **Log in** — passphrase + the current TOTP code
   should land you back on the dashboard.
4. Visit `/ui/admin/`. You should see the overview. (If you see 404,
   bootstrap promotion didn't fire — check `journalctl -u deadman-control`.)
5. `/ui/admin/ledger` → click **Verify chain integrity**. Should
   report `chain=ok`.
6. `/ui/admin/backups` → click **Run backup**. After a few seconds
   the row should flip from `running` to `ok`. (Requires `pg_dump` on
   the host; the script installed it.)
7. `/ui/admin/metrics` — should show non-zero `http.requests` and
   per-route p50/p95.

If all seven pass, the install is functioning end-to-end.

## After install: Day 1 checklist

In Tor Browser:

1. Open `http://your-onion.onion`.
2. Click "Create account" and enter the bootstrap admin email.
3. Choose a 12+ character passphrase. After submit you'll be shown a
   TOTP setup key + 10 recovery codes — save the recovery codes
   offline, configure the TOTP secret in your authenticator app, and
   enter the current 6-digit code to confirm.
4. After login, the top nav has an **Admin** link. That confirms bootstrap
   promotion worked. Visit `/ui/admin/`.
5. Run the **Verify chain** button on `/ui/admin/ledger` — it should say
   "Chain verified". This is your only real-time integrity check.
6. From `/ui/admin/backups`, click **Run backup**. Watch the entry move
   from `running` → `ok`. That confirms pg_dump works on the host and the
   bucket is reachable.
7. From `/ui/admin/config`, set the **Public base URL** to
   `http://your-onion.onion` if it isn't already. (The script does this,
   but verify.)

---

## Day 2 hardening

The default install trades off security for usability in two specific
places. Decide whether each tradeoff is acceptable for your situation.

### 1. Vault passphrases live in `/etc/deadman/deadman.env`

This file is mode 0600, owned by `deadman:deadman`. So an attacker who
gets root on the box can read both passphrases — and at that point they
can also read the vault file and unwrap the release key on their own
schedule.

To harden:

- **Minimum:** ensure the host disk is encrypted (LUKS), so an attacker
  with cold physical access reads nothing without your unlock passphrase
  at boot.
- **Better:** switch to interactive vault unlock. Remove the two
  `DEADMAN_VAULT_PASSPHRASE_*` lines from the env file and restart the
  service. The server will run in a "locked" state — uploads, login, and
  most pages still work, but triggered releases will stall in `unsealing`
  until you SSH in and use `/ui/admin/vault` to unlock. (HTTP unlock is
  on the admin panel, but you must be physically present to type the
  passphrases.)
- **Best:** combine both, plus put one passphrase in a hardware security
  token / OS keyring on a different machine and only assemble them on
  the host at unlock time.

The threshold-vault design *intends* the two passphrases to be held by
two trust domains. The default install puts both in one place because
the alternative is nobody actually using it. If your threat model
deserves the split, do the split.

### 2. The bootstrap admin promotion email is in the env file

After you've used it once, edit `/etc/deadman/deadman.env` and set:

```
DEADMAN_BOOTSTRAP_ADMIN_EMAIL=
```

Then `systemctl restart deadman-control`. Now even an attacker with the
env file cannot conjure another admin via fresh-account signup. (They'd
still need a way to set `is_admin = TRUE` in Postgres directly — which
is logged but not prevented.)

### 3. Tor's hidden-service directory

`/var/lib/tor/deadman/` contains the v3 onion service's private key. Whoever
has that file can impersonate your onion. Tor packages set tight perms on
it by default — don't loosen them. **Back this directory up encrypted**
to your offline backups. If the host dies and you have no backup, the
.onion address dies with it.

### 4. Backups

The admin panel runs pg_dump on demand and uploads to your S3 backup
bucket. **Backups are not encrypted at rest in your bucket** beyond
whatever your storage provider does. If you're using local MinIO, the
backups live on the same disk as Postgres — which means a disk failure
loses both copies. Real self-hosts should point the backup bucket at a
different cloud (Cloudflare R2, Backblaze B2, Wasabi). Edit the env file:

```
DEADMAN_S3_BACKUP_ENDPOINT=https://<region>.<provider>.com
DEADMAN_S3_BACKUP_BUCKET=deadman-yourname-backup
```

Restart the service. Run a fresh backup and verify it lands in the
remote bucket.

### 5. The watchdog (optional but recommended)

`ops/watchdog-worker/` is a Cloudflare Worker cron that hits your onion
every 5 minutes and pages you (via whatever channel you wire up) if the
scheduler hasn't ticked. Without it, a stuck scheduler is silent until
someone misses a release. With it, you get notified within minutes.

---

## Day 60 checklist

- [ ] Run a **restore drill** from one of the admin-panel backups onto
      a throwaway VM. Time it. Document the time-to-recover. Repeat
      every quarter.
- [ ] Verify the offline recovery share is still where you put it.
- [ ] If you ever moved a passphrase to/from a custodian, write down the
      change so you remember who holds what.
- [ ] Re-read [docs/operator-risks.md](operator-risks.md) at this point.
      Some risks only become real once people actually use the system.

---

## Manual install (no script)

If running an unaudited bash script as root makes you twitchy, do it by
hand. The script is idempotent and well-commented; it's intended to be
read.

1. Install prereqs: `sudo apt install tor docker.io docker-compose-plugin`,
   then install Go 1.25+ from https://go.dev/dl/.

2. Create the system user and dirs:
   ```bash
   sudo useradd --system --home /var/lib/deadman --shell /usr/sbin/nologin --user-group deadman
   sudo install -d -m 0750 -o deadman -g deadman /var/lib/deadman /var/log/deadman
   sudo install -d -m 0750                        /etc/deadman
   sudo install -d -m 0755                        /opt/deadman/bin
   ```

3. Build:
   ```bash
   cd control && CGO_ENABLED=0 go build -o /opt/deadman/bin/deadman-control ./cmd/server
   sudo chmod 0755 /opt/deadman/bin/deadman-control
   ```

4. Bring up Docker stack and migrate:
   ```bash
   docker compose -f ops/docker/docker-compose.yml up -d
   cd control && go run github.com/pressly/goose/v3/cmd/goose@latest \
     -dir db/migrations postgres \
     "postgres://deadman:deadman@127.0.0.1:5432/deadman?sslmode=disable" up
   ```

5. Configure Tor:
   ```bash
   sudo install -m 0644 ops/systemd/torrc.deadman.conf /etc/tor/torrc.d/deadman.conf
   # Make sure /etc/tor/torrc has: %include /etc/tor/torrc.d/*.conf
   sudo systemctl reload tor
   sudo cat /var/lib/tor/deadman/hostname
   ```

6. Write `/etc/deadman/deadman.env` from
   `ops/systemd/deadman.env.example`, filling in the onion hostname for
   `DEADMAN_RP_ID` and `DEADMAN_RP_ORIGINS`, and choosing two
   passphrases. `chmod 0600`, `chown deadman:deadman`.

7. Install systemd unit:
   ```bash
   sudo install -m 0644 ops/systemd/deadman-control.service \
     /etc/systemd/system/deadman-control.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now deadman-control
   ```

8. Tail the log to find the share-3 line:
   ```bash
   sudo grep -A 20 "DEADMAN THRESHOLD VAULT CREATED" /var/log/deadman/server.log
   ```
   Record the share. Move on to the Day 1 checklist above.

---

## Uninstall

```bash
sudo systemctl disable --now deadman-control
sudo systemctl reload tor   # after removing /etc/tor/torrc.d/deadman.conf
sudo rm /etc/tor/torrc.d/deadman.conf
sudo rm /etc/systemd/system/deadman-control.service
sudo rm -rf /etc/deadman /var/lib/deadman /var/log/deadman /opt/deadman
sudo userdel deadman
docker compose -f ops/docker/docker-compose.yml down -v
sudo rm -rf /var/lib/tor/deadman   # WARNING: destroys the .onion address
```

The `-v` on docker compose deletes Postgres and MinIO volumes — that's
your DB and your bundles. Don't run that line until you're sure.

---

## Common problems

| Symptom | Diagnosis |
| --- | --- |
| Setup script: "pg_isready not ready in 60 attempts" | Your Postgres container is failing healthcheck. `docker compose -f ops/docker/docker-compose.yml logs postgres` |
| "Tor never produced /var/lib/tor/deadman/hostname" | Tor failed to load the hidden-service config. `journalctl -u tor -n 100`. Common cause: bad permissions on `/var/lib/tor/`. |
| Login rejects valid passphrase + TOTP | Check the VM's clock — TOTP tolerates ±30s drift. `timedatectl status` should show `synchronized: yes`. |
| Lost access to authenticator | Use a recovery code on the login page (link is "Lost your authenticator?"). Recovery codes are single-use; set up a new authenticator afterwards. |
| Login works but "Admin" link doesn't appear | The bootstrap email didn't match the email you registered, or another admin already exists. Either set `is_admin = TRUE` in Postgres for your user, or rerun setup with a different email. |
| Server log shows "vault is locked (no passphrases in env)" | You removed the env passphrases on purpose — see Day 2 hardening §1. Use `/ui/admin/vault` to unlock. If unintentional, restore the env values. |

For everything else, start with `docs/runbook.md`.
