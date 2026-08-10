package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Policy struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Title           string
	Description     string
	ActiveVersionID *uuid.UUID
	State           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type PolicyVersion struct {
	ID                  uuid.UUID
	PolicyID            uuid.UUID
	Version             int
	IntervalDays        int
	GracePeriodHours    int
	HoldPeriodHours     int
	WarningSchedule     json.RawMessage
	CheckInRequirements json.RawMessage
	ReleaseMode         string
	DestinationIDs      []uuid.UUID
	ContentBundleIDs    []uuid.UUID
	EffectiveAt         time.Time
	UserSignature       []byte
	CanonicalHash       []byte
	CreatedAt           time.Time
}

type PolicyState struct {
	PolicyID            uuid.UUID
	ArmedAt             *time.Time
	LastCheckInAt       *time.Time
	LastCheckInDeviceID *uuid.UUID
	NextDueAt           *time.Time
	GraceExpiresAt      *time.Time
	HoldExpiresAt       *time.Time
	TriggerAt           *time.Time
	Epoch               int64
	UpdatedAt           time.Time
}

// CreatePolicy inserts a new (draft) policy.
func CreatePolicy(ctx context.Context, q Querier, userID uuid.UUID, title, description string) (*Policy, error) {
	var p Policy
	err := q.QueryRow(ctx,
		`INSERT INTO policies (user_id, title, description)
		 VALUES ($1,$2,$3)
		 RETURNING id, user_id, title, description, active_version_id, state, created_at, updated_at`,
		userID, title, description,
	).Scan(&p.ID, &p.UserID, &p.Title, &p.Description, &p.ActiveVersionID, &p.State, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	// Create the default runtime row so UPSERT isn't needed on first tick.
	_, err = q.Exec(ctx, `INSERT INTO policy_states (policy_id) VALUES ($1)`, p.ID)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func GetPolicy(ctx context.Context, q Querier, id uuid.UUID) (*Policy, error) {
	var p Policy
	err := q.QueryRow(ctx,
		`SELECT id, user_id, title, description, active_version_id, state, created_at, updated_at
		 FROM policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.UserID, &p.Title, &p.Description, &p.ActiveVersionID, &p.State, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func ListUserPolicies(ctx context.Context, q Querier, userID uuid.UUID) ([]Policy, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, title, description, active_version_id, state, created_at, updated_at
		 FROM policies WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.UserID, &p.Title, &p.Description, &p.ActiveVersionID, &p.State, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreatePolicyVersion inserts a signed, immutable version and marks it active.
// Returns the new version row.
func CreatePolicyVersion(ctx context.Context, q Querier, v *PolicyVersion) (*PolicyVersion, error) {
	// Find next version number.
	var next int
	err := q.QueryRow(ctx,
		`SELECT COALESCE(MAX(version),0) + 1 FROM policy_versions WHERE policy_id = $1`,
		v.PolicyID,
	).Scan(&next)
	if err != nil {
		return nil, err
	}
	v.Version = next
	var out PolicyVersion
	err = q.QueryRow(ctx,
		`INSERT INTO policy_versions
		   (policy_id, version, interval_days, grace_period_hours, hold_period_hours,
		    warning_schedule, check_in_requirements, release_mode,
		    destination_ids, content_bundle_ids, effective_at,
		    user_signature, canonical_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 RETURNING id, policy_id, version, interval_days, grace_period_hours, hold_period_hours,
		           warning_schedule, check_in_requirements, release_mode,
		           destination_ids, content_bundle_ids, effective_at,
		           user_signature, canonical_hash, created_at`,
		v.PolicyID, v.Version, v.IntervalDays, v.GracePeriodHours, v.HoldPeriodHours,
		v.WarningSchedule, v.CheckInRequirements, v.ReleaseMode,
		v.DestinationIDs, v.ContentBundleIDs, v.EffectiveAt,
		v.UserSignature, v.CanonicalHash,
	).Scan(&out.ID, &out.PolicyID, &out.Version, &out.IntervalDays, &out.GracePeriodHours, &out.HoldPeriodHours,
		&out.WarningSchedule, &out.CheckInRequirements, &out.ReleaseMode,
		&out.DestinationIDs, &out.ContentBundleIDs, &out.EffectiveAt,
		&out.UserSignature, &out.CanonicalHash, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	_, err = q.Exec(ctx, `UPDATE policies SET active_version_id = $1, updated_at = now() WHERE id = $2`, out.ID, v.PolicyID)
	return &out, err
}

func GetActivePolicyVersion(ctx context.Context, q Querier, policyID uuid.UUID) (*PolicyVersion, error) {
	var v PolicyVersion
	err := q.QueryRow(ctx,
		`SELECT pv.id, pv.policy_id, pv.version, pv.interval_days, pv.grace_period_hours, pv.hold_period_hours,
		        pv.warning_schedule, pv.check_in_requirements, pv.release_mode,
		        pv.destination_ids, pv.content_bundle_ids, pv.effective_at,
		        pv.user_signature, pv.canonical_hash, pv.created_at
		 FROM policies p JOIN policy_versions pv ON p.active_version_id = pv.id
		 WHERE p.id = $1`, policyID,
	).Scan(&v.ID, &v.PolicyID, &v.Version, &v.IntervalDays, &v.GracePeriodHours, &v.HoldPeriodHours,
		&v.WarningSchedule, &v.CheckInRequirements, &v.ReleaseMode,
		&v.DestinationIDs, &v.ContentBundleIDs, &v.EffectiveAt,
		&v.UserSignature, &v.CanonicalHash, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

// GetPolicyVersionByID loads a specific policy version by its own ID. The
// release worker uses this to release exactly the version pinned in the
// release transaction, not whatever version happens to be active now.
func GetPolicyVersionByID(ctx context.Context, q Querier, versionID uuid.UUID) (*PolicyVersion, error) {
	var v PolicyVersion
	err := q.QueryRow(ctx,
		`SELECT pv.id, pv.policy_id, pv.version, pv.interval_days, pv.grace_period_hours, pv.hold_period_hours,
		        pv.warning_schedule, pv.check_in_requirements, pv.release_mode,
		        pv.destination_ids, pv.content_bundle_ids, pv.effective_at,
		        pv.user_signature, pv.canonical_hash, pv.created_at
		 FROM policy_versions pv
		 WHERE pv.id = $1`, versionID,
	).Scan(&v.ID, &v.PolicyID, &v.Version, &v.IntervalDays, &v.GracePeriodHours, &v.HoldPeriodHours,
		&v.WarningSchedule, &v.CheckInRequirements, &v.ReleaseMode,
		&v.DestinationIDs, &v.ContentBundleIDs, &v.EffectiveAt,
		&v.UserSignature, &v.CanonicalHash, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

// GetPolicyState returns the runtime row, creating it if missing.
func GetPolicyState(ctx context.Context, q Querier, policyID uuid.UUID) (*PolicyState, error) {
	var ps PolicyState
	err := q.QueryRow(ctx,
		`SELECT policy_id, armed_at, last_checkin_at, last_checkin_device_id,
		        next_due_at, grace_expires_at, hold_expires_at, trigger_at, epoch, updated_at
		 FROM policy_states WHERE policy_id = $1`, policyID,
	).Scan(&ps.PolicyID, &ps.ArmedAt, &ps.LastCheckInAt, &ps.LastCheckInDeviceID,
		&ps.NextDueAt, &ps.GraceExpiresAt, &ps.HoldExpiresAt, &ps.TriggerAt, &ps.Epoch, &ps.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &ps, err
}

// GetPolicyStateWithState returns the runtime row plus the policy's current
// lifecycle state, read in a single statement so both come from one snapshot.
// Every writer of policies.state (UpdatePolicyStateCAS) bumps
// policy_states.epoch in the same transaction, so a caller that evaluates a
// transition against this pair and then CASes on the epoch cannot act on a
// state that changed after the read — the epoch would no longer match.
func GetPolicyStateWithState(ctx context.Context, q Querier, policyID uuid.UUID) (*PolicyState, string, error) {
	var ps PolicyState
	var policyState string
	err := q.QueryRow(ctx,
		`SELECT ps.policy_id, ps.armed_at, ps.last_checkin_at, ps.last_checkin_device_id,
		        ps.next_due_at, ps.grace_expires_at, ps.hold_expires_at, ps.trigger_at, ps.epoch, ps.updated_at,
		        p.state
		 FROM policy_states ps JOIN policies p ON p.id = ps.policy_id
		 WHERE ps.policy_id = $1`, policyID,
	).Scan(&ps.PolicyID, &ps.ArmedAt, &ps.LastCheckInAt, &ps.LastCheckInDeviceID,
		&ps.NextDueAt, &ps.GraceExpiresAt, &ps.HoldExpiresAt, &ps.TriggerAt, &ps.Epoch, &ps.UpdatedAt, &policyState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	return &ps, policyState, err
}

// UpdatePolicyStateCAS updates the runtime row only if the epoch matches.
// Returns ErrConcurrentUpdate if the epoch moved under us — caller should
// reload and re-evaluate. last_checkin_device_id is only overwritten when
// deviceID is non-nil, so system transitions (scheduler ticks pass nil)
// preserve the device recorded by the last device check-in.
func UpdatePolicyStateCAS(ctx context.Context, q Querier, ps *PolicyState, expectedEpoch int64, newState string, deviceID *uuid.UUID) error {
	tag, err := q.Exec(ctx,
		`UPDATE policy_states
		 SET armed_at = $2, last_checkin_at = $3,
		     last_checkin_device_id = COALESCE($4, last_checkin_device_id),
		     next_due_at = $5, grace_expires_at = $6, hold_expires_at = $7, trigger_at = $8,
		     epoch = $9, updated_at = now()
		 WHERE policy_id = $1 AND epoch = $10`,
		ps.PolicyID, ps.ArmedAt, ps.LastCheckInAt, deviceID,
		ps.NextDueAt, ps.GraceExpiresAt, ps.HoldExpiresAt, ps.TriggerAt, ps.Epoch,
		expectedEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConcurrentUpdate
	}
	_, err = q.Exec(ctx, `UPDATE policies SET state = $2, updated_at = now() WHERE id = $1`, ps.PolicyID, newState)
	return err
}

// SelectDuePolicyIDs returns up to n armed policy IDs whose next actionable
// deadline (state-dependent) has passed. SKIP LOCKED stops concurrent
// schedulers from selecting the same rows while their selection transactions
// overlap; the locks end when that tx commits, so the epoch CAS in
// UpdatePolicyStateCAS is what actually prevents double-transitions.
func SelectDuePolicyIDs(ctx context.Context, q Querier, now time.Time, n int) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx,
		`SELECT p.id FROM policies p JOIN policy_states ps ON ps.policy_id = p.id
		 WHERE (p.state = 'healthy' AND ps.next_due_at - interval '24 hours' <= $1)
		    OR (p.state = 'warning' AND ps.next_due_at <= $1)
		    OR (p.state = 'grace' AND ps.grace_expires_at <= $1)
		    OR (p.state = 'hold' AND ps.hold_expires_at <= $1)
		 ORDER BY ps.updated_at
		 LIMIT $2
		 FOR UPDATE OF ps SKIP LOCKED`, now, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func ListArmedUserPolicyIDs(ctx context.Context, q Querier, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx,
		`SELECT id FROM policies WHERE user_id = $1
		  AND state IN ('healthy','warning','grace','hold')`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ErrConcurrentUpdate is returned when an optimistic CAS fails.
var ErrConcurrentUpdate = errors.New("store: concurrent update")
