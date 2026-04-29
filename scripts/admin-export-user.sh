#!/usr/bin/env bash
#
# admin-export-user.sh — dump every metadata record tied to a single user
# into a JSON file. Used for abuse-response, subpoena response, account
# closure, or just "what does the platform actually know about user X."
#
# Does NOT include bundle ciphertext (the operator can't read it anyway)
# and does NOT include passkey private material (it never existed
# server-side). Includes:
#
#   - users row
#   - sessions (token hashes only, never the tokens)
#   - webauthn_credentials (public keys, sign counts, AAGUIDs)
#   - devices
#   - policies and active policy_versions
#   - policy_states
#   - content_bundles (metadata only: hashes, sizes, URIs — NOT the bytes)
#   - destinations (config blob included; webhook URLs and email addresses
#     ARE recipient PII; treat the export as sensitive)
#   - release_transactions
#   - audit_events where the user was actor or subject
#
# Usage:
#   sudo ./scripts/admin-export-user.sh user@example.org > user-export.json
#
# Reads /etc/deadman/deadman.env for DEADMAN_DATABASE_URL.

set -euo pipefail

EMAIL="${1:-}"
[[ -n "$EMAIL" ]] || { echo "usage: $0 <email>" >&2; exit 64; }

ENV_FILE="${DEADMAN_ENV_FILE:-/etc/deadman/deadman.env}"
[[ -r "$ENV_FILE" ]] || { echo "cannot read $ENV_FILE; sudo?" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${DEADMAN_DATABASE_URL:?missing in env}"

# psql via the docker container so we don't depend on a host psql.
COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/ops/docker/docker-compose.yml"
PSQL=(docker compose -f "$COMPOSE_FILE" exec -T postgres psql "$DEADMAN_DATABASE_URL" -tAq -F $'\t')

USER_ID="$( "${PSQL[@]}" -c "SELECT id FROM users WHERE email = '$EMAIL'" )"
[[ -n "$USER_ID" ]] || { echo "no user with email $EMAIL" >&2; exit 2; }

# Build a single JSON document via psql's row_to_json + json_agg.
"${PSQL[@]}" <<SQL
\set ON_ERROR_STOP on
\pset format unaligned
\pset tuples_only on
WITH
  u  AS (SELECT to_jsonb(u) - 'identity_pubkey' AS j FROM users u WHERE u.id = '$USER_ID'),
  ss AS (SELECT coalesce(json_agg(json_build_object(
            'id', id, 'device_id', device_id, 'token_hash_hex', encode(token_hash,'hex'),
            'step_up_at', step_up_at, 'expires_at', expires_at,
            'revoked_at', revoked_at, 'created_at', created_at)), '[]'::json) AS j
         FROM sessions WHERE user_id = '$USER_ID'),
  wc AS (SELECT coalesce(json_agg(json_build_object(
            'credential_id_hex', encode(id,'hex'), 'sign_count', sign_count,
            'transports', transports, 'aaguid_hex', encode(aaguid,'hex'),
            'label', label, 'backup_eligible', backup_eligible,
            'backup_state', backup_state, 'created_at', created_at)), '[]'::json) AS j
         FROM webauthn_credentials WHERE user_id = '$USER_ID'),
  dv AS (SELECT coalesce(json_agg(to_jsonb(d)), '[]'::json) AS j
         FROM devices d WHERE user_id = '$USER_ID'),
  po AS (SELECT coalesce(json_agg(to_jsonb(p)), '[]'::json) AS j
         FROM policies p WHERE user_id = '$USER_ID'),
  pv AS (SELECT coalesce(json_agg(to_jsonb(v)), '[]'::json) AS j
         FROM policy_versions v
         WHERE policy_id IN (SELECT id FROM policies WHERE user_id = '$USER_ID')),
  ps AS (SELECT coalesce(json_agg(to_jsonb(s)), '[]'::json) AS j
         FROM policy_states s
         WHERE policy_id IN (SELECT id FROM policies WHERE user_id = '$USER_ID')),
  cb AS (SELECT coalesce(json_agg(json_build_object(
            'id', id, 'version', version, 'wrap_scheme', wrap_scheme,
            'primary_uri', primary_uri, 'backup_uri', backup_uri,
            'size_bytes', size_bytes,
            'ciphertext_sha256_hex', encode(ciphertext_sha256,'hex'),
            'manifest_hash_hex', encode(manifest_hash,'hex'),
            'created_at', created_at, 'deleted_at', deleted_at)), '[]'::json) AS j
         FROM content_bundles WHERE user_id = '$USER_ID'),
  ds AS (SELECT coalesce(json_agg(to_jsonb(d)), '[]'::json) AS j
         FROM destinations d WHERE user_id = '$USER_ID'),
  ae AS (SELECT coalesce(json_agg(json_build_object(
            'seq', seq, 'id', id, 'occurred_at', occurred_at,
            'actor_kind', actor_kind, 'actor_id', actor_id,
            'event_type', event_type,
            'subject_kind', subject_kind, 'subject_id', subject_id,
            'payload', payload,
            'prev_hash_hex', encode(prev_hash,'hex'),
            'payload_hash_hex', encode(payload_hash,'hex'),
            'service_signature_hex', encode(service_signature,'hex'))), '[]'::json) AS j
         FROM audit_events
         WHERE actor_id = '$USER_ID' OR subject_id = '$USER_ID'
         ORDER BY seq ASC)
SELECT jsonb_pretty(jsonb_build_object(
  'export_format_version', 1,
  'exported_at', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'user',         (SELECT j FROM u),
  'sessions',     (SELECT j FROM ss),
  'webauthn_credentials', (SELECT j FROM wc),
  'devices',      (SELECT j FROM dv),
  'policies',     (SELECT j FROM po),
  'policy_versions', (SELECT j FROM pv),
  'policy_states', (SELECT j FROM ps),
  'content_bundles_metadata', (SELECT j FROM cb),
  'destinations', (SELECT j FROM ds),
  'audit_events', (SELECT j FROM ae)
));
SQL
