package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	DeviceID  *uuid.UUID
	TokenHash []byte
	CSRFToken []byte
	StepUpAt  *time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

const sessionCols = `id, user_id, device_id, token_hash, csrf_token, step_up_at, expires_at, revoked_at, created_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.DeviceID, &s.TokenHash, &s.CSRFToken,
		&s.StepUpAt, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func CreateSession(ctx context.Context, q Querier, userID uuid.UUID, deviceID *uuid.UUID, tokenHash []byte, ttl time.Duration) (*Session, error) {
	// step_up_at = now: a freshly-minted session came from a passkey
	// assertion, so the bearer is considered re-authenticated at this moment.
	// csrf_token is server-generated random 32 bytes used to validate
	// state-changing form submissions; rendered to forms as base64url.
	return scanSession(q.QueryRow(ctx,
		`INSERT INTO sessions (user_id, device_id, token_hash, csrf_token, step_up_at, expires_at)
		 VALUES ($1,$2,$3,gen_random_bytes(32),now(),$4)
		 RETURNING `+sessionCols,
		userID, deviceID, tokenHash, time.Now().UTC().Add(ttl),
	))
}

func GetSessionByTokenHash(ctx context.Context, q Querier, tokenHash []byte) (*Session, error) {
	return scanSession(q.QueryRow(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE token_hash = $1`, tokenHash))
}

func RevokeSession(ctx context.Context, q Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, id)
	return err
}
