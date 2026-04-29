package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// StorageMetrics is a snapshot of metadata-only storage state, sourced
// entirely from DB tables (no live bucket scan).
type StorageMetrics struct {
	BundlesTotal         int
	BundlesBytes         int64
	BundlesBackupOK      int
	BundlesNoBackup      int
	DriftEventsLast30d   int64
	PrimaryMissing30d    int64
	ReleasedUnsealSource map[string]int64 // "primary" | "backup"
}

func GetStorageMetrics(ctx context.Context, q Querier) (*StorageMetrics, error) {
	m := &StorageMetrics{ReleasedUnsealSource: map[string]int64{}}
	if err := q.QueryRow(ctx, `
		SELECT count(*), coalesce(sum(size_bytes),0),
		       count(*) FILTER (WHERE backup_uri IS NOT NULL AND backup_uri <> ''),
		       count(*) FILTER (WHERE backup_uri IS NULL OR backup_uri = '')
		FROM content_bundles WHERE deleted_at IS NULL`).Scan(&m.BundlesTotal, &m.BundlesBytes,
		&m.BundlesBackupOK, &m.BundlesNoBackup); err != nil {
		return nil, err
	}
	if err := q.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE event_type = 'bundle.drift'
		                    AND occurred_at > now() - interval '30 days'),
		  count(*) FILTER (WHERE event_type = 'bundle.primary_missing'
		                    AND occurred_at > now() - interval '30 days')
		FROM audit_events`).Scan(&m.DriftEventsLast30d, &m.PrimaryMissing30d); err != nil {
		return nil, err
	}
	// Unseal-source distribution over the last 30d of releases.
	rows, err := q.Query(ctx, `
		SELECT payload->>'source' AS src, count(*)
		FROM audit_events
		WHERE event_type = 'release.unseal_source'
		  AND occurred_at > now() - interval '30 days'
		GROUP BY src`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var src *string
			var n int64
			if err := rows.Scan(&src, &n); err == nil && src != nil {
				m.ReleasedUnsealSource[*src] = n
			}
		}
	}
	return m, nil
}

// StorageIncident is an un-resolved drift or primary-missing event for the
// admin incident list. Unions the two event types.
type StorageIncident struct {
	Seq         int64
	EventType   string
	OccurredAt  time.Time
	SubjectID   *uuid.UUID
	PayloadJSON json.RawMessage
}

func ListStorageIncidents(ctx context.Context, q Querier, limit int) ([]StorageIncident, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := q.Query(ctx, `
		SELECT seq, event_type, occurred_at, subject_id, payload
		FROM audit_events
		WHERE event_type IN ('bundle.drift', 'bundle.primary_missing')
		ORDER BY seq DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageIncident
	for rows.Next() {
		var i StorageIncident
		if err := rows.Scan(&i.Seq, &i.EventType, &i.OccurredAt, &i.SubjectID, &i.PayloadJSON); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
