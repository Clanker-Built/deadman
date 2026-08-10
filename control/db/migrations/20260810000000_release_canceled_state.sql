-- +goose Up
-- +goose StatementBegin
-- Add a 'canceled' terminal state to release_transactions so that revoking or
-- suspending a policy after it has triggered can atomically cancel an
-- in-flight (but not-yet-published) release. Without this, a release that
-- stalled — e.g. the keyvault is locked after a restart — would still fire
-- when the vault later unlocked, publishing the user's content despite a
-- user-visible successful revoke.
ALTER TABLE release_transactions DROP CONSTRAINT release_transactions_state_check;
ALTER TABLE release_transactions ADD CONSTRAINT release_transactions_state_check
    CHECK (state IN ('pending','unsealing','packaging','publishing','completed','failed_partial','failed','canceled'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Collapse any 'canceled' rows to 'failed' before restoring the old constraint
-- so the down migration cannot violate it.
UPDATE release_transactions SET state = 'failed' WHERE state = 'canceled';
ALTER TABLE release_transactions DROP CONSTRAINT release_transactions_state_check;
ALTER TABLE release_transactions ADD CONSTRAINT release_transactions_state_check
    CHECK (state IN ('pending','unsealing','packaging','publishing','completed','failed_partial','failed'));
-- +goose StatementEnd
