#!/usr/bin/env bash
#
# watchdog-poll.sh — independently verify the Deadman scheduler is alive.
#
# Runs on a SEPARATE machine from the control plane. Reaches the onion
# via Tor's SOCKS5 proxy (default 127.0.0.1:9050). Verifies the
# Ed25519-signed heartbeat against a pinned service public key, then
# checks that last_scheduler_tick is fresh enough.
#
# Failure modes that page you:
#   - Onion unreachable or returns non-2xx
#   - Signature does not validate (hostile / man-in-the-middle / wrong key)
#   - last_scheduler_tick is older than STALE_THRESHOLD_SECONDS
#
# Configuration via env vars; see /etc/deadman-watchdog/env on a configured
# host. scripts/setup-watchdog.sh writes a working version of that file.

set -euo pipefail

ENV_FILE="${WATCHDOG_ENV_FILE:-/etc/deadman-watchdog/env}"
if [[ -r "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
fi

: "${WATCHDOG_ONION_URL:?missing — set in $ENV_FILE}"
: "${WATCHDOG_SERVICE_PUBKEY_B64URL:?missing — set in $ENV_FILE}"
STALE_THRESHOLD_SECONDS="${STALE_THRESHOLD_SECONDS:-300}"
ALERT_URL="${ALERT_URL:-}"
ALERT_SHARED_SECRET="${ALERT_SHARED_SECRET:-}"
TOR_SOCKS="${TOR_SOCKS:-127.0.0.1:9050}"

alert() {
  local reason="$1"
  echo "ALERT: $reason" >&2
  if [[ -n "$ALERT_URL" ]]; then
    curl -fsS -X POST -H 'Content-Type: application/json' \
      -H "X-Watchdog-Secret: $ALERT_SHARED_SECRET" \
      --data "$(printf '{"reason":%q,"onion":%q,"at":%q}' "$reason" "$WATCHDOG_ONION_URL" "$(date -u +%FT%TZ)")" \
      "$ALERT_URL" >/dev/null || true
  fi
  exit 1
}

# Fetch via Tor.
RESP="$(curl -fsS --socks5-hostname "$TOR_SOCKS" --max-time 30 \
        "${WATCHDOG_ONION_URL%/}/watchdog" 2>&1)" \
  || alert "watchdog endpoint unreachable: $RESP"

# Required JSON fields: service_pubkey, last_scheduler_tick (RFC3339),
# now (RFC3339), signature (b64url over canonical body). Verification done
# by a small Go tool (verify-watchdog) we ship next to this script.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! echo "$RESP" | "$HERE/verify-watchdog" \
       --pubkey "$WATCHDOG_SERVICE_PUBKEY_B64URL" \
       --max-stale-seconds "$STALE_THRESHOLD_SECONDS"; then
  alert "watchdog verification failed (signature/staleness)"
fi

echo "ok $(date -u +%FT%TZ)"
