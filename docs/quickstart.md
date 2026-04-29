# Quickstart

Five-minute install on a fresh Ubuntu 24.04+ or Debian 12+ VM.

## Prerequisites

- A VM you control (cloud provider or local hypervisor — fine to start
  on home hardware behind a firewall, since the platform is Tor-only).
- SSH access with a user that can run `sudo`.
- ~2 GB RAM, ~10 GB disk, outbound internet access for the install.

That's the entire prereq list. The install script will pull in
Docker, Go, Tor, ufw, and everything else it needs.

## Install

```bash
git clone https://github.com/clanker-built/deadman.git
cd deadman
./scripts/setup-onion.sh
```

The script will:

1. Auto-elevate to root via `sudo` (you'll be prompted once, and
   the elevation banner appears so you don't mistake it for the
   admin-email prompt).
2. Install missing system packages: Docker, Go 1.25, Tor, ufw,
   pg_dump, `qrencode`, etc.
3. Configure ufw: allow SSH only.
4. Prompt for:
   - Admin email (this becomes the bootstrap admin on first login).
   - Two vault passphrases (these unlock the release key — write them
     down).
5. Generate random Postgres + MinIO secrets and a service signing key.
6. Build `deadman-control` (or pick up `./deadman-control` if you
   dropped a prebuilt binary there).
7. Bring up Postgres + MinIO via docker compose, applying migrations.
8. Configure the Tor v3 hidden service in `/etc/tor/torrc`.
9. Install and start the systemd unit.
10. Print your `.onion` URL **and** the offline recovery share. Save
    both — the recovery share is shown only once.

## First login

1. Open Tor Browser. Paste your `.onion` URL.
2. Click **Create account**. Use the same email you gave the script.
3. Choose a passphrase of 12+ characters. Accept the six
   acknowledgments.
4. The TOTP setup page appears:
   - Open your authenticator app (Aegis, KeePassXC, 1Password,
     Bitwarden, etc.). Choose "manual entry."
   - Enter the **setup key** shown on the page; pick TOTP / SHA-1 /
     6 digits / 30 seconds.
   - Save the **10 recovery codes** offline. They're shown once.
   - Enter the current 6-digit code from the app to confirm.
5. You should land on the dashboard. Top nav has an **Admin** link
   (this confirms bootstrap promotion fired).

## Smoke test

On `/ui/admin/`:

- **Ledger** → click **Verify chain integrity**. Should report `chain=ok`.
- **Backups** → click **Run backup**. The row should flip from
  `running` to `ok` within a few seconds.
- **Storage** → primary + backup buckets should both be reachable.

If all three pass, the install is functioning.

## When something goes wrong

| Symptom | First thing to check |
| --- | --- |
| Service crash-loops on start | `sudo journalctl -u deadman-control -n 50` — usually a vault unlock failure or DB connection problem |
| `.onion` URL hangs in Tor Browser | The Tor daemon takes ~30 seconds to publish a fresh descriptor on first start; wait, then refresh |
| Login rejects valid TOTP code | Clock drift on the VM — `timedatectl status` should say `synchronized: yes` |
| Lost authenticator | Login page has a **Lost your authenticator?** disclosure — use one of the 10 recovery codes |

For deeper troubleshooting see [self-hosting.md](self-hosting.md).

## Next steps

- [docs/user-guide.md](user-guide.md) — using the platform once installed.
- [docs/admin-guide.md](admin-guide.md) — operator playbook.
- [docs/operator-risks.md](operator-risks.md) — read this before
  letting anyone but yourself use the instance.
