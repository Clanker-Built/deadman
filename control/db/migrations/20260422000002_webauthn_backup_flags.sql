-- +goose Up
-- +goose StatementBegin
ALTER TABLE webauthn_credentials
    ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN backup_state    BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE webauthn_credentials
    DROP COLUMN backup_eligible,
    DROP COLUMN backup_state;
-- +goose StatementEnd
