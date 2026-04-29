#!/usr/bin/env bash
#
# restore-drill.sh — pull the latest admin-triggered backup from the
# configured object-store bucket, restore it to a throwaway Postgres on
# port 55432, and verify the audit chain inside the restored DB.
#
# Run quarterly (cf. docs/runbook.md §8). Time the run; record the wall
# clock in your ops journal so you can adjust SLA assumptions when it
# starts to slow.
#
# Requires:
#   - docker, docker compose plugin
#   - the deadman-control service to have produced at least one
#     backup (admin panel → Backups → Run backup)
#   - mc (MinIO client) — installed automatically into a docker
#     sidecar so we don't pollute the host
#
# Reads:
#   /etc/deadman/deadman.env  (for S3 endpoint + creds)
#
# This script does NOT touch the live Postgres or the live MinIO. It
# spins up a temporary container, restores into it, and tears it down.

set -euo pipefail

ENV_FILE="${DEADMAN_ENV_FILE:-/etc/deadman/deadman.env}"
DRILL_PORT="${DRILL_PG_PORT:-55432}"
DRILL_NAME="deadman-restore-drill"
WORKDIR=""

cleanup() {
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
  docker rm -f "$DRILL_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -t 1 ]]; then
  C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_GRN=""; C_RED=""; C_BLU=""; C_BLD=""; C_RST=""
fi

step() { printf "\n%s== %s ==%s\n" "${C_BLU}${C_BLD}" "$1" "${C_RST}"; }
ok()   { printf "  %s✓%s %s\n" "${C_GRN}" "${C_RST}" "$1"; }
fail() { printf "  %s✗ %s%s\n" "${C_RED}" "$1" "${C_RST}" >&2; exit 1; }

# Read env (sudo if file is mode 0600 owned by deadman).
if [[ ! -r "$ENV_FILE" ]]; then
  fail "Cannot read $ENV_FILE. Re-run with sudo or set DEADMAN_ENV_FILE."
fi
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${DEADMAN_S3_BACKUP_ENDPOINT:?missing in env}"
: "${DEADMAN_S3_ACCESS_KEY:?missing in env}"
: "${DEADMAN_S3_SECRET_KEY:?missing in env}"
: "${DEADMAN_DATABASE_URL:?missing in env}"

# Default backup bucket name; the manager uses the backup client's bucket.
S3_BACKUP_BUCKET="${DEADMAN_S3_BACKUP_BUCKET:-deadman-backup}"

START_TS="$(date -u +%s)"

step "Locating most-recent backup object"
WORKDIR="$(mktemp -d)"
DUMP_FILE="$WORKDIR/latest.dump.gz"

# Use a transient mc container so we don't depend on host mc.
docker run --rm --network host \
  -e MC_HOST_target="${DEADMAN_S3_BACKUP_ENDPOINT/http:\/\//http://${DEADMAN_S3_ACCESS_KEY}:${DEADMAN_S3_SECRET_KEY}@}" \
  minio/mc:RELEASE.2025-01-17T23-25-50Z \
  ls --json "target/${S3_BACKUP_BUCKET}/backups/" \
  | grep '"type":"file"' \
  | sort \
  | tail -1 \
  | grep -oE '"key":"[^"]+"' | cut -d'"' -f4 > "$WORKDIR/key.txt"

LATEST_KEY="$(cat "$WORKDIR/key.txt")"
[[ -n "$LATEST_KEY" ]] || fail "No backups found in target/${S3_BACKUP_BUCKET}/backups/. Run one from the admin panel first."
ok "Latest: $LATEST_KEY"

step "Downloading backup"
docker run --rm --network host \
  -v "$WORKDIR:/work" \
  -e MC_HOST_target="${DEADMAN_S3_BACKUP_ENDPOINT/http:\/\//http://${DEADMAN_S3_ACCESS_KEY}:${DEADMAN_S3_SECRET_KEY}@}" \
  minio/mc:RELEASE.2025-01-17T23-25-50Z \
  cp "target/${S3_BACKUP_BUCKET}/${LATEST_KEY}" /work/latest.dump.gz
ok "Downloaded $(du -h "$DUMP_FILE" | cut -f1)."

step "Spinning up throwaway Postgres on :${DRILL_PORT}"
docker rm -f "$DRILL_NAME" >/dev/null 2>&1 || true
docker run -d --name "$DRILL_NAME" \
  -e POSTGRES_USER=drill -e POSTGRES_PASSWORD=drill -e POSTGRES_DB=drill \
  -p "127.0.0.1:${DRILL_PORT}:5432" \
  postgres:16.6-alpine >/dev/null
# Wait for ready.
for _ in $(seq 1 30); do
  if docker exec "$DRILL_NAME" pg_isready -U drill -d drill >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ok "Throwaway Postgres ready."

step "Restoring into throwaway DB"
gunzip -c "$DUMP_FILE" | docker exec -i "$DRILL_NAME" \
  pg_restore --no-owner --no-privileges -d drill -U drill --clean --if-exists
ok "pg_restore completed."

step "Verifying audit chain in restored DB"
COUNT=$(docker exec "$DRILL_NAME" psql -U drill -d drill -tAc \
  "SELECT count(*) FROM audit_events;")
ok "audit_events row count: $COUNT"

# Sanity: chain should at least be unbroken at the prev_hash level. Full
# Verify() requires the service public key, which the restored DB carries
# *signatures* for but not the public key itself. Operators with the key
# pinned should run audit.Verify against the restored DB out-of-band.
docker exec "$DRILL_NAME" psql -U drill -d drill -tAc "
  WITH chain AS (
    SELECT seq, prev_hash, payload_hash,
           lag(payload_hash) OVER (ORDER BY seq) AS expected_prev
    FROM audit_events
  )
  SELECT count(*) FROM chain WHERE seq > 1 AND expected_prev <> prev_hash;
" | grep -q '^0$' || fail "Audit chain has hash-link gaps in the restored DB. Investigate: this should never happen if the source DB was healthy."
ok "Audit chain prev_hash links are intact."

END_TS="$(date -u +%s)"
ELAPSED=$(( END_TS - START_TS ))

cat <<EOF

${C_BLD}${C_GRN}Restore drill PASSED${C_RST}

  Backup key:        ${LATEST_KEY}
  Backup size:       $(du -h "$DUMP_FILE" | cut -f1)
  Audit row count:   ${COUNT}
  Time-to-recover:   ${ELAPSED}s

  The throwaway Postgres on :${DRILL_PORT} has been removed.

  ${C_BLD}Next:${C_RST} record this run in your ops journal. If time-to-recover
  is climbing, plan a slimmer backup cadence or a faster bucket.

EOF
