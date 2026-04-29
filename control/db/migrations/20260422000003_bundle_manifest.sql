-- +goose Up
-- +goose StatementBegin
-- Store the manifest bytes alongside the hash so the release worker can
-- reconstruct the same AAD at unseal time.
ALTER TABLE content_bundles
    ADD COLUMN manifest BYTEA;
ALTER TABLE content_bundles
    ADD COLUMN label TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE content_bundles DROP COLUMN manifest;
ALTER TABLE content_bundles DROP COLUMN label;
-- +goose StatementEnd
