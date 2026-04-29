package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ContentBundle struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	Version          int
	Label            string
	ManifestHash     []byte
	Manifest         []byte
	WrappedBundleKey []byte
	WrapScheme       string
	PrimaryURI       string
	BackupURI        *string
	SizeBytes        int64
	CiphertextSHA256 []byte
	CreatedAt        time.Time
	DeletedAt        *time.Time
}

func InsertBundle(ctx context.Context, q Querier, b *ContentBundle) (*ContentBundle, error) {
	var out ContentBundle
	err := q.QueryRow(ctx,
		`INSERT INTO content_bundles
		   (user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		    primary_uri, backup_uri, size_bytes, ciphertext_sha256)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		           primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at`,
		b.UserID, b.Version, b.Label, b.ManifestHash, b.Manifest, b.WrappedBundleKey, b.WrapScheme,
		b.PrimaryURI, b.BackupURI, b.SizeBytes, b.CiphertextSHA256,
	).Scan(&out.ID, &out.UserID, &out.Version, &out.Label, &out.ManifestHash, &out.Manifest, &out.WrappedBundleKey, &out.WrapScheme,
		&out.PrimaryURI, &out.BackupURI, &out.SizeBytes, &out.CiphertextSHA256, &out.CreatedAt, &out.DeletedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func GetBundle(ctx context.Context, q Querier, id uuid.UUID) (*ContentBundle, error) {
	var b ContentBundle
	err := q.QueryRow(ctx,
		`SELECT id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		        primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at
		 FROM content_bundles WHERE id = $1`, id,
	).Scan(&b.ID, &b.UserID, &b.Version, &b.Label, &b.ManifestHash, &b.Manifest, &b.WrappedBundleKey, &b.WrapScheme,
		&b.PrimaryURI, &b.BackupURI, &b.SizeBytes, &b.CiphertextSHA256, &b.CreatedAt, &b.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}

func ListUserBundles(ctx context.Context, q Querier, userID uuid.UUID) ([]ContentBundle, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		        primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at
		 FROM content_bundles WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContentBundle
	for rows.Next() {
		var b ContentBundle
		if err := rows.Scan(&b.ID, &b.UserID, &b.Version, &b.Label, &b.ManifestHash, &b.Manifest, &b.WrappedBundleKey, &b.WrapScheme,
			&b.PrimaryURI, &b.BackupURI, &b.SizeBytes, &b.CiphertextSHA256, &b.CreatedAt, &b.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
