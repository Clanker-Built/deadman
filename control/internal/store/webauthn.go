package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type WebAuthnCredential struct {
	ID             []byte
	UserID         uuid.UUID
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	AAGUID         []byte
	Label          string
	BackupEligible bool
	BackupState    bool
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

func InsertWebAuthnCredential(ctx context.Context, q Querier, c *WebAuthnCredential) error {
	_, err := q.Exec(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, transports, aaguid, label, backup_eligible, backup_state)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.UserID, c.PublicKey, c.SignCount, c.Transports, c.AAGUID, c.Label, c.BackupEligible, c.BackupState)
	if err != nil {
		return fmt.Errorf("insert webauthn credential: %w", err)
	}
	return nil
}

func ListUserCredentials(ctx context.Context, q Querier, userID uuid.UUID) ([]WebAuthnCredential, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, public_key, sign_count, transports, aaguid, label, backup_eligible, backup_state, created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.Label, &c.BackupEligible, &c.BackupState, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func GetCredentialByID(ctx context.Context, q Querier, credID []byte) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	err := q.QueryRow(ctx,
		`SELECT id, user_id, public_key, sign_count, transports, aaguid, label, backup_eligible, backup_state, created_at, last_used_at
		 FROM webauthn_credentials WHERE id = $1`, credID,
	).Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.Label, &c.BackupEligible, &c.BackupState, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

func UpdateCredentialSignCount(ctx context.Context, q Querier, credID []byte, count uint32) error {
	_, err := q.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1, last_used_at = now() WHERE id = $2`,
		count, credID)
	return err
}

// UpdateCredentialFlags records the latest BackupState observed during login.
// BackupState legitimately flips over time as the authenticator syncs/unsyncs.
// BackupEligible is invariant; not updated here.
func UpdateCredentialFlags(ctx context.Context, q Querier, credID []byte, backupState bool) error {
	_, err := q.Exec(ctx,
		`UPDATE webauthn_credentials SET backup_state = $1 WHERE id = $2`, backupState, credID)
	return err
}
