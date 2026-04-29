package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Device struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	Platform         string
	Nickname         string
	DevicePubKey     []byte
	Attestation      []byte
	TrustedAfter     time.Time
	RevokedAt        *time.Time
	LastSeenAt       *time.Time
	PushToken        *string
	PushTokenKind    *string
	MonotonicCounter int64
	CreatedAt        time.Time
}

// CreateDevice inserts a device record. trustedAfter implements the
// delayed-trust window from §29.2 for newly enrolled devices.
func CreateDevice(ctx context.Context, q Querier, d *Device) (*Device, error) {
	var out Device
	err := q.QueryRow(ctx,
		`INSERT INTO devices
		   (user_id, platform, nickname, device_pubkey, attestation, trusted_after, push_token, push_token_kind)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING id, user_id, platform, nickname, device_pubkey, attestation,
		           trusted_after, revoked_at, last_seen_at, push_token, push_token_kind,
		           monotonic_counter, created_at`,
		d.UserID, d.Platform, d.Nickname, d.DevicePubKey, d.Attestation,
		d.TrustedAfter, d.PushToken, d.PushTokenKind,
	).Scan(&out.ID, &out.UserID, &out.Platform, &out.Nickname, &out.DevicePubKey, &out.Attestation,
		&out.TrustedAfter, &out.RevokedAt, &out.LastSeenAt, &out.PushToken, &out.PushTokenKind,
		&out.MonotonicCounter, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func GetDevice(ctx context.Context, q Querier, id uuid.UUID) (*Device, error) {
	var d Device
	err := q.QueryRow(ctx,
		`SELECT id, user_id, platform, nickname, device_pubkey, attestation,
		        trusted_after, revoked_at, last_seen_at, push_token, push_token_kind,
		        monotonic_counter, created_at
		 FROM devices WHERE id = $1`, id,
	).Scan(&d.ID, &d.UserID, &d.Platform, &d.Nickname, &d.DevicePubKey, &d.Attestation,
		&d.TrustedAfter, &d.RevokedAt, &d.LastSeenAt, &d.PushToken, &d.PushTokenKind,
		&d.MonotonicCounter, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func ListUserDevices(ctx context.Context, q Querier, userID uuid.UUID) ([]Device, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, platform, nickname, device_pubkey, attestation,
		        trusted_after, revoked_at, last_seen_at, push_token, push_token_kind,
		        monotonic_counter, created_at
		 FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Platform, &d.Nickname, &d.DevicePubKey, &d.Attestation,
			&d.TrustedAfter, &d.RevokedAt, &d.LastSeenAt, &d.PushToken, &d.PushTokenKind,
			&d.MonotonicCounter, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func RevokeDevice(ctx context.Context, q Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE devices SET revoked_at = now() WHERE id = $1`, id)
	return err
}

// UpdateDeviceCheckIn atomically bumps the monotonic counter (enforcing
// strictly-increasing), updates last_seen_at, and returns the updated row.
// The counter check prevents replay of an older nonce-sign payload.
func UpdateDeviceCheckIn(ctx context.Context, q Querier, id uuid.UUID, newCounter int64) (*Device, error) {
	var d Device
	err := q.QueryRow(ctx,
		`UPDATE devices SET monotonic_counter = $2, last_seen_at = now()
		 WHERE id = $1 AND monotonic_counter < $2
		 RETURNING id, user_id, platform, nickname, device_pubkey, attestation,
		           trusted_after, revoked_at, last_seen_at, push_token, push_token_kind,
		           monotonic_counter, created_at`,
		id, newCounter,
	).Scan(&d.ID, &d.UserID, &d.Platform, &d.Nickname, &d.DevicePubKey, &d.Attestation,
		&d.TrustedAfter, &d.RevokedAt, &d.LastSeenAt, &d.PushToken, &d.PushTokenKind,
		&d.MonotonicCounter, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}
