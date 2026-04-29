-- +goose Up
-- +goose StatementBegin

-- Users: identity anchor. No password column — passkeys only.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           CITEXT UNIQUE NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    -- Root Ed25519 identity public key, registered at account creation.
    identity_pubkey BYTEA,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WebAuthn credentials (passkeys). A user may have many.
CREATE TABLE webauthn_credentials (
    id              BYTEA PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      BYTEA NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT[] NOT NULL DEFAULT '{}',
    aaguid          BYTEA,
    label           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials(user_id);

-- Devices: enrolled mobile hardware with StrongBox/Secure-Enclave public keys.
CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform            TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
    nickname            TEXT NOT NULL DEFAULT '',
    device_pubkey       BYTEA NOT NULL,
    attestation         BYTEA,
    -- Delayed-trust window prevents a freshly-stolen device from acting immediately.
    trusted_after       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    push_token          TEXT,
    push_token_kind     TEXT CHECK (push_token_kind IN ('fcm', 'apns')),
    monotonic_counter   BIGINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX devices_user_id_idx ON devices(user_id);

-- Sessions: short-lived authenticated sessions. Passkey-gated.
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       UUID REFERENCES devices(id) ON DELETE SET NULL,
    token_hash      BYTEA NOT NULL,
    step_up_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sessions_token_hash_idx ON sessions(token_hash);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);

-- Content bundles: encrypted payload objects stored in object storage.
-- The DB holds only metadata and wrapped keys, never plaintext.
CREATE TABLE content_bundles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version             INTEGER NOT NULL DEFAULT 1,
    manifest_hash       BYTEA NOT NULL,
    wrapped_bundle_key  BYTEA NOT NULL,
    -- Wrapping scheme version; allows crypto-agility migrations.
    wrap_scheme         TEXT NOT NULL,
    -- Storage pointers (primary + backup). URIs like s3://bucket/key.
    primary_uri         TEXT NOT NULL,
    backup_uri          TEXT,
    size_bytes          BIGINT NOT NULL,
    ciphertext_sha256   BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX content_bundles_user_id_idx ON content_bundles(user_id);

-- Policies: the deadman configuration. Versioned + signed.
CREATE TABLE policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title                   TEXT NOT NULL,
    description             TEXT NOT NULL DEFAULT '',
    -- Active version points to the latest policy_versions row.
    active_version_id       UUID,
    -- Lifecycle state (§13). See internal/state for the state machine.
    state                   TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft','armed','healthy','warning','grace','hold','triggered','releasing','released','failed_partial','suspended','revoked')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policies_user_id_idx ON policies(user_id);
CREATE INDEX policies_state_idx ON policies(state);

-- Policy versions: immutable, signed. Mutating a policy appends a new version.
CREATE TABLE policy_versions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id               UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version                 INTEGER NOT NULL,
    interval_days           INTEGER NOT NULL CHECK (interval_days BETWEEN 1 AND 365),
    grace_period_hours      INTEGER NOT NULL CHECK (grace_period_hours BETWEEN 1 AND 720),
    hold_period_hours       INTEGER NOT NULL DEFAULT 0,
    warning_schedule        JSONB NOT NULL DEFAULT '[]'::jsonb,
    check_in_requirements   JSONB NOT NULL DEFAULT '{}'::jsonb,
    release_mode            TEXT NOT NULL CHECK (release_mode IN ('private','limited_public','full_public','announcement_only','staged')),
    destination_ids         UUID[] NOT NULL DEFAULT '{}',
    content_bundle_ids      UUID[] NOT NULL DEFAULT '{}',
    -- Applied-at gate implements policy-change cooldowns (§25, M6).
    effective_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Ed25519 signature over a canonical serialization, by the user identity key.
    user_signature          BYTEA NOT NULL,
    canonical_hash          BYTEA NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);

-- Forward-declared FK now that policy_versions exists.
ALTER TABLE policies
    ADD CONSTRAINT policies_active_version_fk
    FOREIGN KEY (active_version_id) REFERENCES policy_versions(id) ON DELETE SET NULL;

-- Policy runtime state: mutable counters driven by the state machine.
CREATE TABLE policy_states (
    policy_id               UUID PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,
    armed_at                TIMESTAMPTZ,
    last_checkin_at         TIMESTAMPTZ,
    last_checkin_device_id  UUID REFERENCES devices(id) ON DELETE SET NULL,
    next_due_at             TIMESTAMPTZ,
    grace_expires_at        TIMESTAMPTZ,
    hold_expires_at         TIMESTAMPTZ,
    trigger_at              TIMESTAMPTZ,
    epoch                   BIGINT NOT NULL DEFAULT 0,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policy_states_next_due_idx ON policy_states(next_due_at);
CREATE INDEX policy_states_grace_expires_idx ON policy_states(grace_expires_at);

-- Destinations: where a policy publishes. Tokens encrypted with integration key.
CREATE TABLE destinations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL CHECK (kind IN ('public_page','email','webhook','mastodon','bluesky','website_repo')),
    label               TEXT NOT NULL,
    config              JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Encrypted credential blob. Encryption scheme version stored alongside.
    encrypted_token     BYTEA,
    token_scheme        TEXT,
    token_expires_at    TIMESTAMPTZ,
    last_verified_at    TIMESTAMPTZ,
    -- Cooldown: when was this destination added/changed? (§25 safeguards)
    effective_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX destinations_user_id_idx ON destinations(user_id);

-- Release transactions: one row per trigger attempt. Idempotent by ID.
CREATE TABLE release_transactions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id               UUID NOT NULL REFERENCES policies(id),
    policy_version_id       UUID NOT NULL REFERENCES policy_versions(id),
    epoch                   BIGINT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN ('pending','unsealing','packaging','publishing','completed','failed_partial','failed')),
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    manifest                JSONB,
    service_signature       BYTEA,
    UNIQUE (policy_id, epoch)
);

CREATE TABLE release_destination_attempts (
    id                      BIGSERIAL PRIMARY KEY,
    release_transaction_id  UUID NOT NULL REFERENCES release_transactions(id) ON DELETE CASCADE,
    destination_id          UUID NOT NULL REFERENCES destinations(id),
    attempt                 INTEGER NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN ('pending','in_flight','ok','failed')),
    last_error              TEXT,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    UNIQUE (release_transaction_id, destination_id, attempt)
);

-- Audit log: append-only, hash-chained for tamper-evidence. No UPDATE/DELETE.
CREATE TABLE audit_events (
    seq             BIGSERIAL PRIMARY KEY,
    id              UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_kind      TEXT NOT NULL CHECK (actor_kind IN ('user','device','service','system','delegate')),
    actor_id        UUID,
    event_type      TEXT NOT NULL,
    subject_kind    TEXT,
    subject_id      UUID,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash       BYTEA NOT NULL,
    payload_hash    BYTEA NOT NULL,
    service_signature BYTEA NOT NULL
);
CREATE INDEX audit_events_subject_idx ON audit_events(subject_kind, subject_id);
CREATE INDEX audit_events_event_type_idx ON audit_events(event_type);

-- Enforce append-only at the DB layer. Only the migration role / DBA can bypass.
CREATE OR REPLACE FUNCTION audit_events_no_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_no_mutation();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_no_mutation();

-- Job queue: Postgres-backed, SKIP LOCKED pattern.
CREATE TABLE jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 10,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','done','failed')),
    locked_at       TIMESTAMPTZ,
    locked_by       TEXT,
    last_error      TEXT,
    -- Idempotency key: duplicate submissions with the same key are no-ops.
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX jobs_ready_idx ON jobs(run_at) WHERE state = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS jobs;
DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS audit_events_no_mutation;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS release_destination_attempts;
DROP TABLE IF EXISTS release_transactions;
DROP TABLE IF EXISTS destinations;
DROP TABLE IF EXISTS policy_states;
ALTER TABLE IF EXISTS policies DROP CONSTRAINT IF EXISTS policies_active_version_fk;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS content_bundles;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
