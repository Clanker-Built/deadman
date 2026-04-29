# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-28

First public release. Alpha quality, provided as-is. See
[SECURITY.md](SECURITY.md) and the README's
[Status and warranty](README.md#status-and-warranty) section for what
that means in practice.

### Added
- **Auth pivot — passphrase + TOTP as primary login.** The previous
  WebAuthn-only flow was unworkable on Tor: Chromium browsers refuse
  WebAuthn on plain-HTTP `.onion` (no trustworthy origin), Tor Browser
  disables `dom.webauthn.enabled` by default and lacks caBLE/QR
  cross-device transport, and Firefox's softtoken is non-persistent.
  The new path is Argon2id (m=64MiB, t=3, p=2) over a 12+ char
  passphrase plus RFC 6238 TOTP (HMAC-SHA1, 30s, 6 digits) plus 10
  single-use 80-bit recovery codes hashed with Argon2id. Works in
  every browser without extensions or `about:config` tweaks. WebAuthn
  code is preserved for opt-in use on TLS-fronted deployments.
- New migration `20260428000000_password_totp.sql`.
- AGPL-3.0 license.
- `SECURITY.md` with coordinated-disclosure process and known-gaps list.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `docs/crypto-spec.md` — canonical reference for crypto primitives.
- Boot-time `audit.Verify` — control plane refuses to start on chain
  break. Override with `DEADMAN_SKIP_AUDIT_VERIFY=1` (logged loudly).
- `LimitCORE=0` in the systemd unit prevents core dumps that could
  leak unsealed key material.
- Session token rotation on step-up reauth — old cookie becomes
  unusable after `/ui/admin/reauth/finish`.
- CSRF protection on `/ui/*` POST endpoints via per-session
  synchronizer tokens.
- User self-service: `/ui/account/export.json` and
  `/ui/account/delete` (with email-confirm + step-up gate).
- `scripts/publish-chain-tip.sh` — daily-cron-friendly external pin
  of the audit-chain tip with the service signature.
- `scripts/restore-drill.sh` — quarterly DR drill harness.
- `scripts/admin-export-user.sh` — abuse-response / subpoena export.
- `scripts/setup-watchdog.sh` + `ops/watchdog-cron/` — Tor-aware
  separate-host watchdog (alternative to the Cloudflare Worker).
- `scripts/setup-onion.sh` — interactive Tor-onion self-host installer
  (Ubuntu/Debian) with random Postgres + MinIO secrets, ufw
  configuration, NTP check, logrotate.
- `destinations.secrets_wrapped` schema column for future webhook
  bearer-token wrapping (not yet wired).

### Changed
- All compose ports now bind to `127.0.0.1` only.
- Postgres + MinIO secrets are randomly generated per install
  (idempotent across re-runs).
- All compose images and the goose migration tool are pinned to
  specific versions.
- `keyvault` recovery share encoding documented as "hex with dashes"
  (was incorrectly described as BIP39).
- `MemoryDenyWriteExecute` removed from systemd unit; documented
  harden-yourself path retained.
- README rewritten for self-host model; mobile references trimmed.
- `SPECS.md` marked historical; current state captured in this file
  and `docs/`.

### Security
- Admin middleware test coverage added for non-admin → 404,
  unauthenticated → /ui/login, stale step-up → /ui/admin/reauth.
- Bootstrap admin promotion now logs a loud warning instructing the
  operator to clear `DEADMAN_BOOTSTRAP_ADMIN_EMAIL` from the env file
  after first use.

## [0.1.0] - TBD

Initial public release. Contains M0–M5 of the original roadmap plus
the admin panel, self-host installer, and supporting documentation.
See README and `docs/self-hosting.md` to start.
