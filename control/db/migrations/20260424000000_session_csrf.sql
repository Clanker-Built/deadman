-- +goose Up
-- +goose StatementBegin
ALTER TABLE sessions ADD COLUMN csrf_token BYTEA;
UPDATE sessions SET csrf_token = gen_random_bytes(32) WHERE csrf_token IS NULL;
ALTER TABLE sessions ALTER COLUMN csrf_token SET NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE sessions DROP COLUMN csrf_token;
-- +goose StatementEnd
