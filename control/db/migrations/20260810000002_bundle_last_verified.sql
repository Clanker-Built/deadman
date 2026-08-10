-- +goose Up
-- +goose StatementBegin
-- Persist when each bundle was last cross-cloud verified so the verifier
-- rotates through all bundles (oldest-verified first) instead of re-checking
-- the same oldest-created N every tick.
ALTER TABLE content_bundles ADD COLUMN last_verified_at TIMESTAMPTZ;
CREATE INDEX content_bundles_verify_due_idx
    ON content_bundles (last_verified_at ASC NULLS FIRST)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS content_bundles_verify_due_idx;
ALTER TABLE content_bundles DROP COLUMN last_verified_at;
-- +goose StatementEnd
