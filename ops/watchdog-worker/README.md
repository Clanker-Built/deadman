# External Watchdog (Cloudflare Worker)

Independent probe that verifies the Deadman control plane is alive and its
scheduler is not silently stalled. Runs on Cloudflare's infrastructure so a
total failure of your own deployment is still detected.

## What it checks

Every minute (configurable cron):

1. `GET <WATCHDOG_URL>` succeeds.
2. Response `service_pubkey` matches the pinned key (detects MitM / unauthorized key rotation).
3. Ed25519 signature over `payload` is valid.
4. `last_scheduler_ms` is within `STALE_THRESHOLD_SECONDS` of now.

Any failure → POST to `ALERT_URL` with a JSON body and log to `wrangler tail`.

## Setup

1. **Pin the public key** from a fresh, authenticated install:

   ```bash
   curl -s https://your-deadman.example.org/watchdog | jq -r .service_pubkey
   ```

   Verify this matches `./service-signing-key.bin` on your control-plane host
   out-of-band. Copy the string into `wrangler.toml` under `SERVICE_PUBKEY_B64URL`.
   **Never auto-trust rotation** — a rotation should be a deliberate human
   ceremony with signed announcement.

2. **Point at your control plane**:

   ```toml
   WATCHDOG_URL = "https://deadman.example.org/watchdog"
   ```

3. **Hook up alerting**. Options:
   - PagerDuty Events API v2 (URL form: `https://events.pagerduty.com/v2/enqueue`)
   - Slack Incoming Webhook
   - A second independent mailer (e.g., Pushover API)
   - A webhook you poll yourself from a phone app

   Set `ALERT_URL` and optionally `ALERT_SHARED_SECRET` (sent as
   `x-watchdog-secret` header — use if your receiver supports pre-shared
   auth).

4. **Deploy**:

   ```bash
   cd ops/watchdog-worker
   npm i -g wrangler   # one-time
   wrangler login      # one-time
   wrangler deploy
   ```

5. **Test** — trigger the `fetch` handler manually:

   ```bash
   curl https://deadman-watchdog.<your-subdomain>.workers.dev/
   ```

   You should get `{"ok": true, "age_seconds": <small>}`. If you then stop
   the control plane's scheduler, within `STALE_THRESHOLD_SECONDS` + the
   cron interval your alert fires.

## Threat model

What this protects against:
- Scheduler dies silently (process alive, ticker stuck).
- Whole control plane down (no release can fire).
- Key substitution / MitM (pinned pubkey check).

What this does NOT protect against:
- Cloudflare itself going down during a critical release. If that's in your
  threat model, add a second independent watchdog (e.g., a Hetzner VM cron
  running the same JS via Deno).

## Key rotation

If you ever rotate `service-signing-key.bin`:

1. Announce the planned rotation in your audit log with a timestamp.
2. Drain pending releases.
3. Rotate key.
4. Update `SERVICE_PUBKEY_B64URL` in `wrangler.toml` and redeploy.
5. Verify the watchdog alerts you didn't accept the rotation by pinging the
   old endpoint once to confirm it now fails.
