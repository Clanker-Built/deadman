#!/usr/bin/env bash
#
# publish-chain-tip.sh — emit the latest audit-chain hash + a service
# signature over it, in a small JSON envelope you can publish to a public
# location.
#
# Why: the audit ledger is hash-chained and signed, but all of those
# signatures and hashes live in YOUR database. An attacker with full
# DB access can rewrite history and re-sign with the (compromised)
# service signing key. The mitigation is to externally pin the chain tip
# at known points in time — git commits to a public repo, posts to
# Bluesky/ntfy/Slack, anything timestamped that you don't control.
#
# Run as a daily cron. Output goes to stdout (so you can pipe it). The
# verifier reads two pins from different days and confirms the chain
# between them is consistent + signed by the pinned service pubkey.
#
# Usage:
#   sudo ./scripts/publish-chain-tip.sh > /var/lib/deadman/pins/$(date -u +%Y%m%d).json

set -euo pipefail

ENV_FILE="${DEADMAN_ENV_FILE:-/etc/deadman/deadman.env}"
[[ -r "$ENV_FILE" ]] || { echo "cannot read $ENV_FILE; sudo?" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${DEADMAN_DATABASE_URL:?missing in env}"

COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/ops/docker/docker-compose.yml"

# Pull the latest chain tip — the row with the largest seq.
# We export hex of payload_hash, the corresponding ed25519 signature,
# and the seq + occurred_at so a verifier can locate it.
PSQL=(docker compose -f "$COMPOSE_FILE" exec -T postgres psql "$DEADMAN_DATABASE_URL" -tAq)

TIP="$(
  "${PSQL[@]}" -c "
    SELECT json_build_object(
      'pin_format_version', 1,
      'pinned_at',          to_char(now() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
      'seq',                seq,
      'occurred_at',        to_char(occurred_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
      'event_id',            id,
      'prev_hash_hex',      encode(prev_hash, 'hex'),
      'payload_hash_hex',   encode(payload_hash, 'hex'),
      'service_signature_b64url', regexp_replace(
                                    regexp_replace(
                                      encode(service_signature, 'base64'),
                                      '\\+', '-', 'g'),
                                    '/', '_', 'g')
    )
    FROM audit_events ORDER BY seq DESC LIMIT 1;
  "
)"
[[ -n "$TIP" ]] || { echo "no audit events to pin (chain is empty)" >&2; exit 2; }

# Strip = padding from base64 of the signature for url-safe-ness.
TIP="${TIP//=/}"

# Pretty-print if jq is around; pass through otherwise.
if command -v jq >/dev/null 2>&1; then
  echo "$TIP" | jq .
else
  echo "$TIP"
fi
