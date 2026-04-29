package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Destination struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Kind           string
	Label          string
	Config         json.RawMessage
	EncryptedToken []byte
	TokenScheme    *string
	TokenExpiresAt *time.Time
	LastVerifiedAt *time.Time
	EffectiveAt    time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

func CreateDestination(ctx context.Context, q Querier, d *Destination) (*Destination, error) {
	var out Destination
	err := q.QueryRow(ctx,
		`INSERT INTO destinations (user_id, kind, label, config, encrypted_token, token_scheme)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, user_id, kind, label, config, encrypted_token, token_scheme,
		           token_expires_at, last_verified_at, effective_at, revoked_at, created_at`,
		d.UserID, d.Kind, d.Label, d.Config, d.EncryptedToken, d.TokenScheme,
	).Scan(&out.ID, &out.UserID, &out.Kind, &out.Label, &out.Config, &out.EncryptedToken,
		&out.TokenScheme, &out.TokenExpiresAt, &out.LastVerifiedAt, &out.EffectiveAt,
		&out.RevokedAt, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func ListUserDestinations(ctx context.Context, q Querier, userID uuid.UUID) ([]Destination, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, kind, label, config, encrypted_token, token_scheme,
		        token_expires_at, last_verified_at, effective_at, revoked_at, created_at
		 FROM destinations WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Destination
	for rows.Next() {
		var d Destination
		if err := rows.Scan(&d.ID, &d.UserID, &d.Kind, &d.Label, &d.Config, &d.EncryptedToken,
			&d.TokenScheme, &d.TokenExpiresAt, &d.LastVerifiedAt, &d.EffectiveAt,
			&d.RevokedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func GetDestination(ctx context.Context, q Querier, id uuid.UUID) (*Destination, error) {
	var d Destination
	err := q.QueryRow(ctx,
		`SELECT id, user_id, kind, label, config, encrypted_token, token_scheme,
		        token_expires_at, last_verified_at, effective_at, revoked_at, created_at
		 FROM destinations WHERE id = $1`, id,
	).Scan(&d.ID, &d.UserID, &d.Kind, &d.Label, &d.Config, &d.EncryptedToken,
		&d.TokenScheme, &d.TokenExpiresAt, &d.LastVerifiedAt, &d.EffectiveAt,
		&d.RevokedAt, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func RevokeDestination(ctx context.Context, q Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE destinations SET revoked_at = now() WHERE id = $1`, id)
	return err
}
