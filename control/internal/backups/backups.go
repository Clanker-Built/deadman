// Package backups manages on-demand pg_dump snapshots to object storage.
//
// Restore is deliberately NOT a web action — it belongs in the runbook +
// a CLI. This package only handles capture + listing + retention GC.
package backups

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// Manager runs backups on demand. One shared instance for the process.
type Manager struct {
	Logger      *slog.Logger
	Store       *store.Store
	Ledger      *audit.Ledger
	Destination *storage.Client // where to write backups (prefer the backup bucket)
	// DatabaseURL is the Postgres DSN passed to pg_dump. Sensitive.
	DatabaseURL string
	// KeepCount: keep this many successful backups; older ones are GC'd.
	// <= 0 disables retention (keep everything).
	KeepCount int

	// running enforces the single-flight contract behind ErrAlreadyRunning:
	// concurrent Run calls must not stack pg_dump child processes.
	running atomic.Bool
}

// ErrAlreadyRunning is returned if a Run is invoked while one is in flight.
var ErrAlreadyRunning = errors.New("backup: another backup is in progress")

// ErrPgDumpMissing is returned when pg_dump is not on PATH.
var ErrPgDumpMissing = errors.New("backup: pg_dump not found on PATH")

// Run executes pg_dump --format=custom | gzip, uploads to object storage,
// records the row, runs retention GC, and emits an audit event. Synchronous
// (caller should spawn a goroutine if needed); safe to call from an HTTP
// handler — the whole thing finishes in seconds-to-minutes for a solo-scale
// DB.
func (m *Manager) Run(ctx context.Context, actor uuid.UUID) (*store.AdminBackup, error) {
	if m == nil || m.Destination == nil {
		return nil, errors.New("backup: no storage destination configured")
	}
	if !m.running.CompareAndSwap(false, true) {
		return nil, ErrAlreadyRunning
	}
	defer m.running.Store(false)
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return nil, ErrPgDumpMissing
	}

	ts := time.Now().UTC().Format("20060102-150405")
	id := uuid.New()
	key := fmt.Sprintf("backups/pgdump-%s-%s.dump.gz", ts, id.String())

	rec, err := store.InsertBackup(ctx, m.Store.Pool, actor, m.Destination.Bucket(), key)
	if err != nil {
		return nil, fmt.Errorf("insert backup row: %w", err)
	}

	size, sha, runErr := m.runPipeline(ctx, key)
	status := "ok"
	errMsg := ""
	if runErr != nil {
		status = "failed"
		errMsg = runErr.Error()
	}
	if err := store.FinishBackup(ctx, m.Store.Pool, rec.ID, status, size, sha[:], errMsg); err != nil {
		m.Logger.Warn("backup finish row update", "err", err)
	}

	payload := map[string]any{
		"backup_id": rec.ID.String(),
		"bucket":    m.Destination.Bucket(),
		"key":       key,
		"size":      size,
		"status":    status,
	}
	if runErr != nil {
		payload["error"] = runErr.Error()
	}
	if _, err := m.Ledger.Append(ctx, m.Store, audit.Event{
		ActorKind: audit.ActorUser, ActorID: &actor,
		EventType: "admin.backup_completed",
		Payload:   payload,
	}); err != nil {
		m.Logger.Warn("backup audit append", "err", err)
	}

	if runErr != nil {
		return rec, runErr
	}
	// Retention GC: on success only. A failed run shouldn't prune.
	if m.KeepCount > 0 {
		if err := m.gc(ctx); err != nil {
			m.Logger.Warn("backup retention GC", "err", err)
		}
	}
	// Refresh to return the final row state.
	final, _ := store.GetBackup(ctx, m.Store.Pool, rec.ID)
	if final != nil {
		return final, nil
	}
	return rec, nil
}

// runPipeline spawns pg_dump, compresses through gzip, tees into a temp
// file on disk (so we can compute sha256 and get a ReadSeeker for S3 Put),
// then uploads. Returns uncompressed-archive size is hard to know; we report
// compressed size instead, which is what matters for storage accounting.
func (m *Manager) runPipeline(ctx context.Context, key string) (int64, [32]byte, error) {
	var zero [32]byte
	tmp, err := os.CreateTemp("", "deadman-pgdump-*.gz")
	if err != nil {
		return 0, zero, fmt.Errorf("tempfile: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup even on error paths.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	gz := gzip.NewWriter(tmp)

	// Run pg_dump. --format=custom produces a file that pg_restore reads.
	// --no-owner / --no-privileges keep the dump portable across environments.
	cmd := exec.CommandContext(ctx, "pg_dump", // #nosec G204 -- argv is fixed literals plus m.DatabaseURL, set once at startup from operator env (DEADMAN_DATABASE_URL); no shell, never request/DB-derived
		"--format=custom", "--no-owner", "--no-privileges",
		m.DatabaseURL)
	cmd.Stdout = gz
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return 0, zero, fmt.Errorf("pg_dump: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := gz.Close(); err != nil {
		return 0, zero, fmt.Errorf("gzip close: %w", err)
	}
	// Seek + sha256.
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return 0, zero, err
	}
	h := sha256.New()
	size, err := io.Copy(h, tmp)
	if err != nil {
		return 0, zero, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))

	// Upload.
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return 0, zero, err
	}
	if _, err := m.Destination.Put(ctx, key, tmp, "application/gzip"); err != nil {
		return 0, zero, fmt.Errorf("s3 put: %w", err)
	}
	return size, sum, nil
}

func (m *Manager) gc(ctx context.Context) error {
	rows, err := store.ListBackupsForRetention(ctx, m.Store.Pool)
	if err != nil {
		return err
	}
	excess := len(rows) - m.KeepCount
	if excess <= 0 {
		return nil
	}
	for _, b := range rows[:excess] {
		if b.Bucket != m.Destination.Bucket() {
			// Row was written to a different destination than the one
			// currently configured (bucket migration). Deleting through the
			// current client would target the wrong endpoint/bucket — leave
			// it for manual cleanup per the runbook.
			m.Logger.Warn("backup GC skipping row recorded on a different bucket",
				"id", b.ID, "row_bucket", b.Bucket, "current_bucket", m.Destination.Bucket())
			continue
		}
		if _, err := m.Destination.RawS3().DeleteObject(ctx, &awss3.DeleteObjectInput{
			Bucket: aws.String(b.Bucket), Key: aws.String(b.Key),
		}); err != nil {
			m.Logger.Warn("backup delete object", "key", b.Key, "err", err)
			continue
		}
		if err := store.MarkBackupDeleted(ctx, m.Store.Pool, b.ID); err != nil {
			m.Logger.Warn("backup mark deleted", "id", b.ID, "err", err)
		}
	}
	return nil
}
