# Security Policy

## Reporting a vulnerability

**Do not file a public issue.** Use GitHub's
[private security advisory](https://github.com/clanker-built/deadman/security/advisories/new)
form, which is the preferred channel for this repository. Include:

- A description of the vulnerability and its impact
- Steps to reproduce
- Affected commit hash or release tag
- Whether you want credit in the disclosure (and how to attribute)

GitHub Security Advisories provide an end-to-end private channel
without requiring GPG; if you prefer GPG, attach an encrypted
description to the advisory.

This repository is published as-is with no guaranteed support, but
we do triage security reports as a courtesy:

- Acknowledging receipt within **3 business days**.
- Providing a triage assessment within **10 business days**.
- A fix or workaround for confirmed high-severity issues within
  **30 days**, or a public statement explaining why longer is needed.
- Crediting the reporter in the changelog and release notes unless
  asked otherwise.

## Supported versions

This is a young project. Until v1.0:

- Only the `main` branch and the most recent tagged release receive
  security fixes.
- Self-hosters should pull and rebuild on every release; there is no
  hot-patch / LTS path.

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md) for the per-row
threat-to-mitigation mapping. See
[`docs/operator-risks.md`](docs/operator-risks.md) for the
operator-side risks the platform's design *cannot* mitigate (legal
compulsion, deanonymization of the operator, abuse-by-users). Reading
those before disclosing helps us triage faster.

## Known gaps

We track known unpatched issues openly so reporters don't waste
effort and so operators know what to compensate for at deployment.
The list is not exhaustive but covers everything we're currently aware
of as of the most recent release.

### Cryptography / data handling

- **No third-party security audit has been performed.** We have written
  the threat model honestly and the cryptographic primitives are
  standard library / well-reviewed, but no firm has independently
  reviewed the running code. Self-host operators with high-stakes use
  cases should commission their own review. Cost: $30k-$150k for a
  focused crypto + protocol audit.
- **Webhook destination secrets are not yet wrapped.** A
  `destinations.secrets_wrapped` column exists in schema but is unused;
  current webhook destinations either rely on signed-body authentication
  (Ed25519 over the manifest) or post to no-auth endpoints. If you point
  a webhook at an endpoint that requires bearer auth in the URL,
  that token is currently stored plaintext in `destinations.config`.
- **Audit chain is signed but not externally pinned by the platform.**
  Operators should run `scripts/publish-chain-tip.sh` on a daily cron
  and publish the output to a public, timestamped location they don't
  control. Without an external pin, an attacker with full DB and
  signing-key access can rewrite history undetectably.
- **The unsealed release private key lives in process memory** while
  the vault is unlocked. `LimitCORE=0` in the systemd unit prevents
  core-dump leakage; `mlock`-ing the memory is not currently done.
  An attacker with full host root access can read process memory
  directly via `/proc/<pid>/mem` regardless.

### Auth / sessions

- **Session step-up is reauth-by-cookie-presentation, not a fresh
  passkey assertion.** When a user clicks "Confirm and continue" on
  the reauth page, the server rotates their session token (revoking
  the old) but does not require a fresh `navigator.credentials.get()`
  call. A future hardening pass will add a true second-factor
  ceremony bound to a server-issued challenge. In the meantime, an
  attacker with the cookie can step up to admin within the cookie
  TTL — the cookie itself is the limiting factor.
- **CSRF protection is in place on `/ui/*` POSTs** via synchronizer
  tokens, but only when there's a session. Pre-session POSTs to
  `/api/v1/auth/*` rely on the WebAuthn ceremony's challenge binding
  for replay protection, which is correct but is not "CSRF protection"
  in the OWASP sense.
- **No rate limit on `/ui/login` specifically.** Argon2id verification
  takes ~100ms per attempt which provides natural throttling; layered
  IP/email rate limits are wired on the `/api/v1/auth/login/*` JSON
  endpoints (used by native clients) but not yet on the browser POST
  handler. Brute-forcing a 12-char passphrase at 10/sec is still
  infeasible, but a layered limit is queued for the next pass.
- **TOTP secret is stored as base32 plaintext** in
  `users.totp_secret_wrapped` (column name is forward-looking). DB
  read access is already root-equivalent to the platform; vault-wrap
  of the secret is queued for the next pass to bring it inline with
  destination secrets / SMTP password handling.

### Operations

- **Postgres uses superuser credentials for the application.** A
  least-privilege application role would limit blast radius if the
  application were ever exploited; the audit-log append-only trigger
  already prevents the most damaging tampering even from superuser.
- **Tor hidden-service private key backup is the operator's
  responsibility.** Loss of `/var/lib/tor/deadman/` permanently
  destroys the .onion address. We document this; we do not back it
  up automatically.
- **No proactive alerting** beyond the optional watchdog. If the
  watchdog isn't deployed, a stuck scheduler is silent until someone
  notices a missed release.

### Out of scope

- Vulnerabilities in **third-party authenticator software** (Bitwarden,
  1Password, browser passkey UIs). Report those upstream.
- Vulnerabilities in **Tor** itself. Report to the Tor Project.
- Vulnerabilities in **Postgres**, **MinIO**, the **Linux kernel**,
  Go's standard library, or the AWS SDK. Report upstream.
- Misconfigurations of operator deployments that depart from the
  defaults in `scripts/setup-onion.sh`. We document the safe defaults;
  operators who change them are responsible for their own threat model.
- The legal exposure of operating an instance for others. See
  [`docs/operator-risks.md`](docs/operator-risks.md). That is a real
  set of risks but they are not "vulnerabilities" in this codebase.

## Disclosure

We coordinate disclosure with reporters. Default timeline:

- **Day 0:** Report received.
- **Day 0-3:** Acknowledged.
- **Day 0-10:** Triage assessment shared with reporter.
- **Day N:** Fix prepared and tested.
- **Day N+7:** Fix released to `main`. Reporter may verify before
  public disclosure.
- **Day N+14:** CVE filed (if applicable) and public advisory
  published, including credit to the reporter unless declined.

Critical severity issues compress this timeline. Low severity issues
may be batched into the next release with notes in `CHANGELOG.md`.

If the maintainer becomes unresponsive, reporters may publicly
disclose after **90 days** without further coordination.
