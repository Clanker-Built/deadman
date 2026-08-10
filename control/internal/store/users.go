package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type User struct {
	ID             uuid.UUID
	Email          string
	DisplayName    string
	IdentityPubKey []byte
	Status         string
	IsAdmin        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const userCols = `id, email, display_name, identity_pubkey, status, is_admin, created_at, updated_at`

func scanUser(row interface {
	Scan(dest ...any) error
}) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.IdentityPubKey, &u.Status, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a new user. The email is case-insensitive (CITEXT).
// identityPubKey may be nil and set later when the client finishes enrollment.
func CreateUser(ctx context.Context, q Querier, email, displayName string, identityPubKey []byte) (*User, error) {
	u, err := scanUser(q.QueryRow(ctx,
		`INSERT INTO users (email, display_name, identity_pubkey)
		 VALUES ($1, $2, $3)
		 RETURNING `+userCols,
		email, displayName, identityPubKey,
	))
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// CreateUserWithID inserts a new user with a caller-chosen ID. WebAuthn
// registration needs this: the ID doubles as the passkey user handle fixed
// at BeginRegister, before any row exists.
func CreateUserWithID(ctx context.Context, q Querier, id uuid.UUID, email, displayName string, identityPubKey []byte) (*User, error) {
	u, err := scanUser(q.QueryRow(ctx,
		`INSERT INTO users (id, email, display_name, identity_pubkey)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+userCols,
		id, email, displayName, identityPubKey,
	))
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

func GetUserByEmail(ctx context.Context, q Querier, email string) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

func GetUserByID(ctx context.Context, q Querier, id uuid.UUID) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// SetPasswordHash writes the Argon2id-encoded passphrase hash.
func SetPasswordHash(ctx context.Context, q Querier, id uuid.UUID, hash string) error {
	_, err := q.Exec(ctx, `UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, hash, id)
	return err
}

// GetPasswordHash returns the encoded hash, or "" if none set.
func GetPasswordHash(ctx context.Context, q Querier, id uuid.UUID) (string, error) {
	var h *string
	err := q.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, id).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", nil
	}
	return *h, nil
}

// SetTOTPWrapped stores the vault-wrapped TOTP secret. confirmedAt is set
// when the user proves possession of the authenticator with a valid code.
func SetTOTPWrapped(ctx context.Context, q Querier, id uuid.UUID, wrapped []byte, confirmed bool) error {
	if confirmed {
		_, err := q.Exec(ctx,
			`UPDATE users SET totp_secret_wrapped = $1, totp_confirmed_at = now(), updated_at = now() WHERE id = $2`,
			wrapped, id)
		return err
	}
	_, err := q.Exec(ctx,
		`UPDATE users SET totp_secret_wrapped = $1, totp_confirmed_at = NULL, updated_at = now() WHERE id = $2`,
		wrapped, id)
	return err
}

// GetTOTPWrapped returns (wrappedSecret, confirmedAt). Both nil when the
// user has not enrolled.
func GetTOTPWrapped(ctx context.Context, q Querier, id uuid.UUID) ([]byte, *time.Time, error) {
	var wrapped []byte
	var confirmed *time.Time
	err := q.QueryRow(ctx,
		`SELECT totp_secret_wrapped, totp_confirmed_at FROM users WHERE id = $1`, id).
		Scan(&wrapped, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return wrapped, confirmed, nil
}

// SetRecoveryCodes replaces the user's recovery code hash list.
func SetRecoveryCodes(ctx context.Context, q Querier, id uuid.UUID, hashed []string) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET recovery_codes_hashed = $1, updated_at = now() WHERE id = $2`,
		hashed, id)
	return err
}

// GetRecoveryCodes returns the user's stored recovery hash list.
func GetRecoveryCodes(ctx context.Context, q Querier, id uuid.UUID) ([]string, error) {
	var codes []string
	err := q.QueryRow(ctx, `SELECT recovery_codes_hashed FROM users WHERE id = $1`, id).Scan(&codes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// DeleteUser removes a user row, cascading to webauthn_credentials,
// sessions, devices, policies, content_bundles, destinations via the
// existing FK ON DELETE CASCADE. Audit events stay (the actor_id
// becomes orphaned but the rows remain — the audit chain must NOT
// be broken). The caller is responsible for emitting a final
// account.deleted audit event BEFORE calling this.
func DeleteUser(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
