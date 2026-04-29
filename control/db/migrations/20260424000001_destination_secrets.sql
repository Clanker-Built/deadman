-- +goose Up
-- +goose StatementBegin
-- destinations.secrets_wrapped holds optional auth material (bearer
-- tokens, signing secrets, OAuth refresh tokens) wrapped with the
-- release public key using the same RSA-OAEP+AES-GCM scheme as bundle
-- DEKs. Unwrap requires the threshold vault unlocked. NULL = no
-- per-destination secret; the destination authenticates via the
-- service Ed25519 signature over the manifest body or via no auth at
-- all (public landing page, anonymous webhook).
--
-- The wire shape stored here is opaque to the DB; only the release
-- worker (with the unsealed private key) can decrypt it. Schema is
-- in place now so future destination-kind code can opt in without
-- another migration; current destination kinds (public_page, email,
-- webhook) do NOT use it yet.
ALTER TABLE destinations ADD COLUMN secrets_wrapped BYTEA;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE destinations DROP COLUMN secrets_wrapped;
-- +goose StatementEnd
