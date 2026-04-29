-- +goose Up
-- +goose StatementBegin
CREATE TABLE admin_backups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    actor_id    UUID REFERENCES users(id),
    bucket      TEXT NOT NULL,
    key         TEXT NOT NULL,
    size_bytes  BIGINT,
    sha256      BYTEA,
    -- status: running | ok | failed | deleted
    status      TEXT NOT NULL DEFAULT 'running',
    error       TEXT
);
CREATE INDEX admin_backups_started_idx ON admin_backups (started_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_backups;
-- +goose StatementEnd
