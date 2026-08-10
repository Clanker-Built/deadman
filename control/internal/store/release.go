package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ReleaseTransaction struct {
	ID               uuid.UUID
	PolicyID         uuid.UUID
	PolicyVersionID  uuid.UUID
	Epoch            int64
	State            string
	StartedAt        time.Time
	CompletedAt      *time.Time
	Manifest         json.RawMessage
	ServiceSignature []byte
}

// CreateOrGetReleaseTransaction inserts a pending release_transactions row
// for (policy_id, epoch) or returns the existing row. Idempotent.
func CreateOrGetReleaseTransaction(ctx context.Context, q Querier, policyID, versionID uuid.UUID, epoch int64) (*ReleaseTransaction, bool, error) {
	var rt ReleaseTransaction
	err := q.QueryRow(ctx,
		`INSERT INTO release_transactions (policy_id, policy_version_id, epoch, state)
		 VALUES ($1, $2, $3, 'pending')
		 ON CONFLICT (policy_id, epoch) DO NOTHING
		 RETURNING id, policy_id, policy_version_id, epoch, state, started_at, completed_at, manifest, service_signature`,
		policyID, versionID, epoch,
	).Scan(&rt.ID, &rt.PolicyID, &rt.PolicyVersionID, &rt.Epoch, &rt.State, &rt.StartedAt, &rt.CompletedAt, &rt.Manifest, &rt.ServiceSignature)
	if err == nil {
		return &rt, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	// Already existed — fetch.
	err = q.QueryRow(ctx,
		`SELECT id, policy_id, policy_version_id, epoch, state, started_at, completed_at, manifest, service_signature
		 FROM release_transactions WHERE policy_id = $1 AND epoch = $2`, policyID, epoch,
	).Scan(&rt.ID, &rt.PolicyID, &rt.PolicyVersionID, &rt.Epoch, &rt.State, &rt.StartedAt, &rt.CompletedAt, &rt.Manifest, &rt.ServiceSignature)
	return &rt, false, err
}

// FindPendingReleases returns release transactions that still need work.
//
// The join on policies.state = 'releasing' is a safety gate: a policy that was
// revoked or suspended after triggering must never have its release advanced,
// even if the atomic cancel in the revoke path was somehow missed. Both
// conditions are required — the release row must be unfinished AND the policy
// must still be in the releasing state.
func FindPendingReleases(ctx context.Context, q Querier, limit int) ([]ReleaseTransaction, error) {
	rows, err := q.Query(ctx,
		`SELECT rt.id, rt.policy_id, rt.policy_version_id, rt.epoch, rt.state, rt.started_at, rt.completed_at, rt.manifest, rt.service_signature
		 FROM release_transactions rt
		 JOIN policies p ON p.id = rt.policy_id
		 WHERE rt.state IN ('pending','unsealing','packaging','publishing')
		   AND p.state = 'releasing'
		 ORDER BY rt.started_at ASC LIMIT $1 FOR UPDATE OF rt SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReleaseTransaction
	for rows.Next() {
		var rt ReleaseTransaction
		if err := rows.Scan(&rt.ID, &rt.PolicyID, &rt.PolicyVersionID, &rt.Epoch, &rt.State, &rt.StartedAt, &rt.CompletedAt, &rt.Manifest, &rt.ServiceSignature); err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// UpdateReleaseState advances a release transaction to a new state.
func UpdateReleaseState(ctx context.Context, q Querier, id uuid.UUID, newState string) error {
	_, err := q.Exec(ctx, `UPDATE release_transactions SET state = $1 WHERE id = $2`, newState, id)
	return err
}

// CancelOpenReleasesForPolicy marks every not-yet-finished release transaction
// for a policy as 'canceled'. Called in the same transaction as a revoke or
// suspend so the cancellation is atomic with the policy state change: a
// release that has not yet published is stopped before it can. Returns the
// number of rows canceled. Rows already in a terminal state are untouched.
func CancelOpenReleasesForPolicy(ctx context.Context, q Querier, policyID uuid.UUID) (int64, error) {
	tag, err := q.Exec(ctx,
		`UPDATE release_transactions
		   SET state = 'canceled', completed_at = now()
		 WHERE policy_id = $1
		   AND state IN ('pending','unsealing','packaging','publishing')`, policyID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// FinishRelease sets the manifest + signature and marks completed.
func FinishRelease(ctx context.Context, q Querier, id uuid.UUID, newState string, manifest json.RawMessage, sig []byte) error {
	_, err := q.Exec(ctx,
		`UPDATE release_transactions
		   SET state = $1, manifest = $2, service_signature = $3, completed_at = now()
		 WHERE id = $4`, newState, manifest, sig, id)
	return err
}

// DestinationDelivered reports whether a destination already has a successful
// delivery for this release, so a resumed or retried run skips it instead of
// delivering twice (idempotency across crashes and concurrent workers).
func DestinationDelivered(ctx context.Context, q Querier, releaseID, destID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM release_destination_attempts
		   WHERE release_transaction_id = $1 AND destination_id = $2 AND state = 'ok'
		 )`, releaseID, destID).Scan(&ok)
	return ok, err
}

// CountDestinationAttempts returns how many attempts a destination has already
// had for this release, so the next attempt is numbered correctly and a
// bounded retry cap can be enforced.
func CountDestinationAttempts(ctx context.Context, q Querier, releaseID, destID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx,
		`SELECT count(*) FROM release_destination_attempts
		 WHERE release_transaction_id = $1 AND destination_id = $2`, releaseID, destID).Scan(&n)
	return n, err
}

// RecordDestinationAttempt inserts a per-destination attempt row.
func RecordDestinationAttempt(ctx context.Context, q Querier, releaseID, destID uuid.UUID, attempt int, state string, lastErr string) error {
	var errPtr *string
	if lastErr != "" {
		errPtr = &lastErr
	}
	_, err := q.Exec(ctx,
		`INSERT INTO release_destination_attempts (release_transaction_id, destination_id, attempt, state, last_error, started_at, completed_at)
		 VALUES ($1, $2, $3, $4, $5, now(), CASE WHEN $4 IN ('ok','failed') THEN now() ELSE NULL END)`,
		releaseID, destID, attempt, state, errPtr)
	return err
}

// ListTriggeredPoliciesNeedingRelease finds policies in 'triggered' state for
// which we haven't yet created a release transaction at the current epoch.
func ListTriggeredPoliciesNeedingRelease(ctx context.Context, q Querier, limit int) ([]struct {
	PolicyID        uuid.UUID
	PolicyVersionID uuid.UUID
	Epoch           int64
}, error) {
	rows, err := q.Query(ctx,
		// No NOT-EXISTS filter on release_transactions: a policy is listed as
		// long as it is still 'triggered'. Creating the release row and
		// advancing the policy to 'releasing' happen in two transactions, so a
		// failure between them can leave a row created but the policy still
		// 'triggered'. Re-listing it (CreateOrGet is idempotent, ReleaseStarted
		// is a no-op once 'releasing') lets the next tick finish the advance
		// instead of wedging the policy forever.
		`SELECT p.id, p.active_version_id, ps.epoch
		 FROM policies p
		 JOIN policy_states ps ON ps.policy_id = p.id
		 WHERE p.state = 'triggered'
		   AND p.active_version_id IS NOT NULL
		 LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row = struct {
		PolicyID        uuid.UUID
		PolicyVersionID uuid.UUID
		Epoch           int64
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.PolicyID, &r.PolicyVersionID, &r.Epoch); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
