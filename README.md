# Deadman

**A zero-knowledge deadman's switch and controlled-release platform.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg)](https://go.dev/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status-and-warranty)

You upload encrypted material, define a check-in schedule, and tell
Deadman who to send the material to if you stop checking in. The
server cannot read your material, and a hash-chained signed audit log
makes every action it takes verifiable after the fact.

> **This is alpha software, provided as-is, with no warranty and no
> support.** See [Status and warranty](#status-and-warranty). It is
> intentionally not a hosted service — see
> [docs/operator-risks.md](docs/operator-risks.md).
**Created in memory of mysteriously missing or dead scientists and whistleblowers.**

---

## Table of contents

- [What this is](#what-this-is)
- [What this isn't](#what-this-isnt)
- [Quickstart — self-host as a Tor onion](#quickstart--self-host-as-a-tor-onion)
- [Documentation](#documentation)
- [Architecture at a glance](#architecture-at-a-glance)
- [Repository layout](#repository-layout)
- [Local development](#local-development)
- [Status and warranty](#status-and-warranty)
- [License](#license)

---

## What this is

- A **Go control plane** with a server-rendered web UI, a release
  scheduler, and a tamper-evident audit ledger.
- **Zero-knowledge by design.** Bundle ciphertext is what the server
  sees; the release key is split 2-of-3 (Shamir) across two
  passphrases plus an offline recovery share, and is reconstructed
  in memory only at release time.
- **Postgres** primary data store with a hash-chained, server-signed
  audit table whose tip can be pinned externally for after-the-fact
  verification.
- **Multi-cloud S3-compatible storage** (primary + backup) with
  consistency checking between them.
- **Passphrase + TOTP authentication** (Argon2id + RFC 6238 + 10
  single-use recovery codes), workable on Tor without browser
  extensions or hardware keys. WebAuthn is preserved as opt-in for
  TLS-fronted deployments.
- A **single-script installer** for self-hosting on a Tor v3 onion
  service: vanilla Ubuntu/Debian VM in, working `.onion` URL out.

---

## What this isn't

- **Not a hosted service.** No public instance is operated. Anyone
  hosting this for strangers should read
  [docs/operator-risks.md](docs/operator-risks.md) first.
- **Not a publication or distribution platform.** It releases material
  to destinations *you* configure (a public landing page on
  storage you own, email recipients, or a webhook). It does not
  cross-post to social platforms.
- **Not a panic button.** Minimum 24-hour warning window plus a
  separate grace period are floors that cannot be removed.
- **Not finished.** Mobile apps, HSM support, hosted distribution,
  and several enterprise features in [SPECS.md](SPECS.md) are
  deliberately out of scope for this build.

---

## Quickstart — self-host as a Tor onion

On a vanilla Ubuntu 24.04+ or Debian 12+ install with nothing but SSH
access:

```bash
git clone https://github.com/clanker-built/deadman.git
cd deadman
./scripts/setup-onion.sh
```

The script auto-elevates with sudo, installs Docker + Go + Tor + ufw +
a few utilities (anything missing), configures the firewall, prompts
for an admin email and two vault passphrases, generates random
Postgres + MinIO secrets, builds the binary, brings up Postgres +
MinIO, applies migrations, configures the Tor onion, writes the env
file, and starts a systemd service. It prints your `.onion` URL and
the offline recovery share at the end.

Total time: 2–5 minutes on a fresh VM.

For a step-by-step walkthrough with screenshots, the manual fallback,
and day-2 hardening, see [docs/quickstart.md](docs/quickstart.md) and
[docs/self-hosting.md](docs/self-hosting.md).

---

## Documentation

| Audience | Document | What it covers |
| --- | --- | --- |
| Anyone | [docs/quickstart.md](docs/quickstart.md) | Five-minute install on a fresh VM |
| Anyone | [docs/use-cases.md](docs/use-cases.md) | What this is for, and what it isn't |
| Operator | [docs/self-hosting.md](docs/self-hosting.md) | Full install guide with manual fallback |
| Operator | [docs/admin-guide.md](docs/admin-guide.md) | Day-to-day operation: bootstrap, vault, ledger, backups |
| Operator | [docs/operator-risks.md](docs/operator-risks.md) | **Read before hosting for anyone but yourself** |
| Operator | [docs/runbook.md](docs/runbook.md) | Incident procedures: vault rotation, drift response, restore |
| End user | [docs/user-guide.md](docs/user-guide.md) | Register, set up TOTP, create a policy, arm it, check in |
| Auditor | [docs/threat-model.md](docs/threat-model.md) | Threats and design responses |
| Auditor | [docs/crypto-spec.md](docs/crypto-spec.md) | Single-source crypto reference |
| Maintainer | [SECURITY.md](SECURITY.md) | Vulnerability reporting + known gaps |
| Maintainer | [CHANGELOG.md](CHANGELOG.md) | Per-version changes |
| Maintainer | [SPECS.md](SPECS.md) | Original full product specification (historical) |

---

## Architecture at a glance

```
                      ┌────────────────────────────┐
                      │  Tor v3 hidden service     │
                      │  (your-onion.onion :80)    │
                      └────────────┬───────────────┘
                                   │
                                   ▼
                      ┌────────────────────────────┐
                      │  deadman-control (Go)      │
                      │  - server-rendered UI      │
                      │  - REST/JSON API           │
                      │  - scheduler               │
                      │  - release worker          │
                      │  - audit ledger (signed)   │
                      └─┬─────────┬──────────────┬─┘
                        │         │              │
                        ▼         ▼              ▼
                 ┌──────────┐  ┌──────┐  ┌────────────────┐
                 │ Postgres │  │MinIO │  │ Vault file     │
                 │ (data +  │  │(S3-  │  │ (Shamir 2-of-3 │
                 │  audit)  │  │ comp)│  │  release key)  │
                 └──────────┘  └──────┘  └────────────────┘
```

The vault file holds the release key encrypted under a 2-of-3 Shamir
threshold split: two passphrase-derived shares (Argon2id) and one
offline recovery share. The release key is reconstructed in memory
only when an unsealed bundle needs to be released; the server never
holds plaintext at rest.

---

## Repository layout

| Path | Contents |
| --- | --- |
| `control/` | Go server, all internal packages, DB migrations |
| `scripts/` | Setup, watchdog, restore-drill, admin-export, chain-pin scripts |
| `ops/docker/` | Postgres + MinIO docker-compose (loopback-only binds) |
| `ops/systemd/` | systemd unit, env-file template, torrc snippet, logrotate |
| `ops/watchdog-cron/` | Tor-aware separate-host watchdog (cron + Go verifier) |
| `ops/watchdog-worker/` | Cloudflare Worker watchdog for clearnet hosts (alternative) |
| `docs/` | Operator, user, auditor documentation |
| `.github/workflows/` | CI: vet, test, golangci-lint, govulncheck |

`android/` and `ios/` directories are reserved as placeholders only.
No native mobile source has been written; browser access works fine
including from Tor Browser for Android.

---

## Local development

For local-only dev (no Tor, HTTPS via mkcert):

```bash
make up        # docker stack
make migrate   # apply migrations
make dev-run   # server on https://deadman.local:8443
make test      # go test ./... -race
```

See `ops/dev.env` for the development environment variables it expects.

---

## Status and warranty

This is **alpha software, version 0.1.0**, released for inspection,
audit, and self-hosting by people willing to read the source first.

- **No warranty.** Use at your own risk. The threat model
  ([docs/threat-model.md](docs/threat-model.md)) describes what the
  software tries to defend against; nothing is promised beyond that.
- **No support.** This repository is published as-is. The maintainers
  do not provide installation help, troubleshooting, or feature
  requests over email or chat.
- **Issues and pull requests from outside contributors are not
  accepted.** Fork freely under the AGPL — see
  [LICENSE](LICENSE) — but do not expect upstream review or merge.
  See [CONTRIBUTING.md](CONTRIBUTING.md) for the rationale.
- **Security disclosures are an exception.** If you find a
  vulnerability, please report it privately as described in
  [SECURITY.md](SECURITY.md).

If you cannot accept those terms, do not run this software.

---

## License

[AGPL-3.0](LICENSE). The threat model depends on the running code
matching the published code; the AGPL's source-disclosure obligation
for network services makes that property enforceable in practice.

If you modify this code and run it as a network service, you are
required to publish your modifications under the same license. That is
not incidental — it is load-bearing for the project's claims about
what the running server is and is not doing.
