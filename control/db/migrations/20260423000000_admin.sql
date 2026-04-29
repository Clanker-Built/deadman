-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX users_is_admin_idx ON users (is_admin) WHERE is_admin = TRUE;

-- server_settings is a single-row table holding admin-editable runtime
-- config. Env vars remain the fallback source of truth; DB values override
-- env when present. Secrets are stored encrypted (wrapped_value) — never
-- plaintext. For the lean build we wrap with the vault public key using
-- the same scheme as bundle DEKs, so a DB leak alone reveals nothing.
CREATE TABLE server_settings (
    id                    INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    smtp_host             TEXT,
    smtp_port             INTEGER,
    smtp_username         TEXT,
    smtp_password_wrapped BYTEA,
    smtp_from             TEXT,
    smtp_insecure_skip    BOOLEAN NOT NULL DEFAULT FALSE,
    public_base_url       TEXT,
    rate_limit_login_per_min   INTEGER,
    rate_limit_checkin_per_min INTEGER,
    updated_by            UUID REFERENCES users(id),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO server_settings (id) VALUES (1) ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS server_settings;
DROP INDEX IF EXISTS users_is_admin_idx;
ALTER TABLE users DROP COLUMN is_admin;
-- +goose StatementEnd
