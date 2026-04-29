-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Intentionally do not drop shared extensions on down.
-- +goose StatementEnd
