-- +goose Up
-- +goose StatementBegin
-- Auth pivot: passphrase + TOTP as primary auth path. WebAuthn becomes
-- opt-in. All three columns are NULLABLE because:
--   - existing users created via WebAuthn have no password and we don't
--     want to break them (they remain WebAuthn-only until they set one);
--   - TOTP enrollment is a second step after registration;
--   - recovery codes are issued only on TOTP enrollment.
ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN totp_secret_wrapped BYTEA;
ALTER TABLE users ADD COLUMN totp_confirmed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN recovery_codes_hashed TEXT[];
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN totp_secret_wrapped;
ALTER TABLE users DROP COLUMN totp_confirmed_at;
ALTER TABLE users DROP COLUMN recovery_codes_hashed;
-- +goose StatementEnd
