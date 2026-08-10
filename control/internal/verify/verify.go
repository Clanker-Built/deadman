// Package verify runs periodic cross-cloud consistency checks on stored
// bundles. For each recently-uploaded (or randomly-sampled older) bundle,
// the verifier hashes the ciphertext on primary and backup and compares.
//
// Drift outcomes:
//   - match → record a success timestamp, done.
//   - primary missing → audit 'bundle.primary_missing'; release will fall
//     back to backup automatically (§29.3).
//   - backup missing → audit 'bundle.backup_missing'; user durability is
//     degraded to single-cloud until re-uploaded.
//   - both missing → audit 'bundle.both_missing' (critical; operator alert).
//   - hash mismatch → audit 'bundle.drift' (critical; possible bit-rot or
//     tamper). Worker does not self-heal; operator investigates.
//
// The stored-canonical hash (content_bundles.ciphertext_sha256 at upload
// time) is the source of truth for what "should" be there.
package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

type Worker struct {
	Store     *store.Store
	Primary   *storage.Client
	Backup    *storage.Client
	Ledger    *audit.Ledger
	Logger    *slog.Logger
	BatchSize int
	// StaleAfter selects bundles not verified in at least this duration.
	// 0 means verify every tick regardless (useful for tests).
	StaleAfter time.Duration
}

func New(w Worker) *Worker {
	if w.BatchSize == 0 {
		w.BatchSize = 20
	}
	if w.StaleAfter == 0 {
		w.StaleAfter = 12 * time.Hour
	}
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	return &w
}

// Tick verifies up to BatchSize bundles whose last verification is older
// than StaleAfter. Safe to call concurrently from multiple schedulers; each
// verification is side-effect-free except for the audit event.
func (w *Worker) Tick(ctx context.Context) error {
	if w.Primary == nil || w.Backup == nil {
		return nil // single-cloud; nothing to compare
	}
	bundles, err := w.selectStale(ctx)
	if err != nil {
		return err
	}
	for _, b := range bundles {
		if err := w.verifyOne(ctx, b); err != nil {
			w.Logger.Warn("verify: one", "bundle_id", b.ID, "err", err)
		}
		if err := w.markVerified(ctx, b.ID); err != nil {
			w.Logger.Warn("verify: mark verified", "bundle_id", b.ID, "err", err)
		}
	}
	return nil
}

func (w *Worker) selectStale(ctx context.Context) ([]store.ContentBundle, error) {
	// Due = never verified, or last verified more than StaleAfter ago.
	// Oldest-verified first (NULLs first) so every bundle rotates through.
	cutoff := time.Now().Add(-w.StaleAfter)
	rows, err := w.Store.Pool.Query(ctx,
		`SELECT id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		        primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at
		 FROM content_bundles
		 WHERE deleted_at IS NULL
		   AND (last_verified_at IS NULL OR last_verified_at < $1)
		 ORDER BY last_verified_at ASC NULLS FIRST, created_at ASC
		 LIMIT $2`, cutoff, w.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ContentBundle
	for rows.Next() {
		var b store.ContentBundle
		if err := rows.Scan(&b.ID, &b.UserID, &b.Version, &b.Label, &b.ManifestHash, &b.Manifest,
			&b.WrappedBundleKey, &b.WrapScheme, &b.PrimaryURI, &b.BackupURI, &b.SizeBytes,
			&b.CiphertextSHA256, &b.CreatedAt, &b.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (w *Worker) verifyOne(ctx context.Context, b store.ContentBundle) error {
	primaryKey := keyFromURI(b.PrimaryURI)
	var backupKey string
	if b.BackupURI != nil {
		backupKey = keyFromURI(*b.BackupURI)
	}
	if primaryKey == "" && backupKey == "" {
		return errors.New("verify: bundle has no storage URIs")
	}

	pHash, pErr := storageHash(ctx, w.Primary, primaryKey)
	bHash, bErr := storageHash(ctx, w.Backup, backupKey)

	var kind string
	payload := map[string]any{
		"bundle_id":        b.ID,
		"canonical_sha256": hex.EncodeToString(b.CiphertextSHA256),
		"primary_error":    errString(pErr),
		"backup_error":     errString(bErr),
	}
	switch {
	case pErr != nil && bErr != nil:
		kind = "bundle.both_missing"
	case pErr != nil:
		kind = "bundle.primary_missing"
		payload["backup_sha256"] = hex.EncodeToString(bHash[:])
	case bErr != nil:
		kind = "bundle.backup_missing"
		payload["primary_sha256"] = hex.EncodeToString(pHash[:])
	case pHash != bHash:
		kind = "bundle.drift"
		payload["primary_sha256"] = hex.EncodeToString(pHash[:])
		payload["backup_sha256"] = hex.EncodeToString(bHash[:])
	default:
		// Match: only audit if the stored canonical hash also matches.
		canon := [32]byte{}
		copy(canon[:], b.CiphertextSHA256)
		if canon != pHash {
			kind = "bundle.drift"
			payload["primary_sha256"] = hex.EncodeToString(pHash[:])
			payload["note"] = "primary matches backup but not canonical — stored hash may be wrong"
		} else {
			// Healthy; no audit event to avoid log noise.
			return nil
		}
	}
	_, err := w.Ledger.Append(ctx, w.Store, audit.Event{
		ActorKind:   audit.ActorService,
		EventType:   kind,
		SubjectKind: "bundle",
		SubjectID:   &b.ID,
		Payload:     payload,
	})
	return err
}

func storageHash(ctx context.Context, c *storage.Client, key string) ([32]byte, error) {
	if c == nil || key == "" {
		return [32]byte{}, errors.New("client or key missing")
	}
	h, _, err := c.HeadSHA256(ctx, key)
	return h, err
}

// keyFromURI parses s3://bucket/path/to/key → path/to/key.
func keyFromURI(uri string) string {
	rest := strings.TrimPrefix(uri, "s3://")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[i+1:]
	}
	return ""
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// markVerified stamps the bundle's last_verified_at after a check attempt,
// whatever the outcome — findings are recorded in the audit ledger, and
// re-checking a broken bundle every tick would hammer both clouds without
// producing new signal.
func (w *Worker) markVerified(ctx context.Context, id uuid.UUID) error {
	_, err := w.Store.Pool.Exec(ctx,
		`UPDATE content_bundles SET last_verified_at = now() WHERE id = $1`, id)
	return err
}
