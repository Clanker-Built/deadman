# Tor-aware Watchdog (cron)

This is the watchdog flavor for **onion-only self-hosts**. It runs on a
host that is *separate* from the control plane (a small VPS, an old
laptop, anything that's reliably online and isn't on the same physical
infrastructure as the Deadman host).

The watchdog reaches the control plane through Tor's SOCKS proxy. Each
firing it:

1. GETs `http://<your-onion>/watchdog` via Tor.
2. Decodes the JSON, confirms the embedded `service_pubkey` matches the
   pinned key in `env`, verifies the Ed25519 signature over
   `"tick=<last_scheduler_tick>|now=<now>"`.
3. Confirms `now - last_scheduler_tick` is below the staleness threshold.
4. POSTs an alert to your configured URL on any failure.

If you have a clearnet control plane instead of an onion, the
Cloudflare-Worker version in `../watchdog-worker/` is simpler. Use one or
the other, not both.

## Install

```bash
sudo ./scripts/setup-watchdog.sh
```

Run this from the repo root *on the watchdog host* (not the Deadman host).
It will:

- Install Tor and Go (if missing).
- Build `verify-watchdog`.
- Place files at `/usr/local/bin/watchdog-poll.sh`,
  `/usr/local/bin/verify-watchdog`.
- Prompt for your onion URL, the pinned service pubkey, and an alert
  URL.
- Write `/etc/deadman-watchdog/env` (mode 0640).
- Install a systemd timer at `/etc/systemd/system/deadman-watchdog.timer`
  that fires every 5 minutes.

After install, force-fire it once to confirm:

```bash
sudo systemctl start deadman-watchdog.service
sudo journalctl -u deadman-watchdog.service -n 50
```

You should see `ok <timestamp>` if the Deadman onion is healthy. Force a
failure to test alerting (stop deadman-control on the other host, wait
for the next firing, confirm the alert lands).

## Why a separate host

If the Deadman control plane and its watchdog run on the same machine,
a hardware/host failure takes both down silently — and the missed
release is exactly what the watchdog is meant to detect. The whole
point is *independent failure modes*. Pick a host that:

- Is on a different cloud provider, or different physical location.
- Has different network routing (different ISP if possible).
- Doesn't share a control plane (different SSH keys, different
  admin user).

Don't put the watchdog on a free tier that goes dormant when idle. The
free tier dormancy *is itself a watchdog failure*.

## Files

- `watchdog-poll.sh` — the polling shell script.
- `verify-watchdog/main.go` — the small Go signature verifier.
- `env.example` — template for `/etc/deadman-watchdog/env`.
- (`../watchdog-worker/`) — alternative Cloudflare Worker for clearnet.
