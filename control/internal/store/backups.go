package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminBackup is one backup attempt record.
type AdminBackup struct {
	ID         uuid.UUID
	StartedAt  time.Time
	FinishedAt *time.Time
	ActorID    *uuid.UUID
	Bucket     string
	Key        string
	SizeBytes  *int64
	SHA256     []byte
	Status     string // running | ok | failed | deleted
	Error      *string
}

func InsertBackup(ctx context.Context, q Querier, actor uuid.UUID, bucket, key string) (*AdminBackup, error) {
	var b AdminBackup
	err := q.QueryRow(ctx, `
		INSERT INTO admin_backups (actor_id, bucket, key)
		VALUES ($1, $2, $3)
		RETURNING id, started_at, finished_at, actor_id, bucket, key,
		          size_bytes, sha256, status, error`,
		actor, bucket, key,
	).Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.ActorID, &b.Bucket, &b.Key,
		&b.SizeBytes, &b.SHA256, &b.Status, &b.Error)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func FinishBackup(ctx context.Context, q Querier, id uuid.UUID, status string, sizeBytes int64, sha []byte, errMsg string) error {
	var errPtr *string
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := q.Exec(ctx, `
		UPDATE admin_backups SET
			finished_at = now(),
			size_bytes = $2, sha256 = $3, status = $4, error = $5
		WHERE id = $1`, id, sizeBytes, sha, status, errPtr)
	return err
}

func MarkBackupDeleted(ctx context.Context, q Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx,
		`UPDATE admin_backups SET status = 'deleted' WHERE id = $1`, id)
	return err
}

func ListBackups(ctx context.Context, q Querier, limit int) ([]AdminBackup, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := q.Query(ctx, `
		SELECT id, started_at, finished_at, actor_id, bucket, key,
		       size_bytes, sha256, status, error
		FROM admin_backups
		ORDER BY started_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminBackup
	for rows.Next() {
		var b AdminBackup
		if err := rows.Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.ActorID,
			&b.Bucket, &b.Key, &b.SizeBytes, &b.SHA256, &b.Status, &b.Error); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListBackupsForRetention returns the OK-status backups oldest-first for the
// retention GC to trim.
func ListBackupsForRetention(ctx context.Context, q Querier) ([]AdminBackup, error) {
	rows, err := q.Query(ctx, `
		SELECT id, started_at, finished_at, actor_id, bucket, key,
		       size_bytes, sha256, status, error
		FROM admin_backups
		WHERE status = 'ok'
		ORDER BY started_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminBackup
	for rows.Next() {
		var b AdminBackup
		if err := rows.Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.ActorID,
			&b.Bucket, &b.Key, &b.SizeBytes, &b.SHA256, &b.Status, &b.Error); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func GetBackup(ctx context.Context, q Querier, id uuid.UUID) (*AdminBackup, error) {
	var b AdminBackup
	err := q.QueryRow(ctx, `
		SELECT id, started_at, finished_at, actor_id, bucket, key,
		       size_bytes, sha256, status, error
		FROM admin_backups WHERE id = $1`, id,
	).Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.ActorID, &b.Bucket, &b.Key,
		&b.SizeBytes, &b.SHA256, &b.Status, &b.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}
