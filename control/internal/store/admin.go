package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminOverviewStats is a single snapshot for the admin overview page.
// Nothing here reveals ciphertext, passphrases, or destination secrets —
// metadata only.
type AdminOverviewStats struct {
	UsersTotal          int
	UsersActive7d       int
	UsersAdmin          int
	PoliciesTotal       int
	PoliciesArmed       int
	PoliciesTriggered   int
	PoliciesReleased    int
	BundlesTotal        int
	BundlesBytes        int64
	DestinationsTotal   int
	AuditEventsTotal    int64
	AuditLast24h        int64
	SchedulerLastTickAt *time.Time
}

// GetAdminOverview aggregates counters in a handful of cheap queries.
// Runs against the pool; no tx needed — eventually consistent snapshot.
func GetAdminOverview(ctx context.Context, q Querier) (*AdminOverviewStats, error) {
	s := &AdminOverviewStats{}
	if err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM users),
		(SELECT count(*) FROM users WHERE updated_at > now() - interval '7 days'),
		(SELECT count(*) FROM users WHERE is_admin = TRUE),
		(SELECT count(*) FROM policies),
		(SELECT count(*) FROM policies WHERE state IN ('armed','healthy','warning','grace','hold')),
		(SELECT count(*) FROM policies WHERE state = 'triggered'),
		(SELECT count(*) FROM policies WHERE state = 'released'),
		(SELECT count(*) FROM content_bundles),
		(SELECT coalesce(sum(size_bytes),0) FROM content_bundles),
		(SELECT count(*) FROM destinations WHERE revoked_at IS NULL),
		(SELECT count(*) FROM audit_events),
		(SELECT count(*) FROM audit_events WHERE occurred_at > now() - interval '24 hours')
	`).Scan(
		&s.UsersTotal, &s.UsersActive7d, &s.UsersAdmin,
		&s.PoliciesTotal, &s.PoliciesArmed, &s.PoliciesTriggered, &s.PoliciesReleased,
		&s.BundlesTotal, &s.BundlesBytes,
		&s.DestinationsTotal, &s.AuditEventsTotal, &s.AuditLast24h,
	); err != nil {
		return nil, err
	}
	return s, nil
}

// AdminUserRow is a compact per-user view for the admin user list.
type AdminUserRow struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
	Status      string
	IsAdmin     bool
	CreatedAt   time.Time
	PolicyCount int
	ArmedCount  int
	BundleCount int
	BundleBytes int64
}

func ListAdminUsers(ctx context.Context, q Querier, limit, offset int) ([]AdminUserRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		SELECT u.id, u.email, u.display_name, u.status, u.is_admin, u.created_at,
		       (SELECT count(*) FROM policies p WHERE p.user_id = u.id),
		       (SELECT count(*) FROM policies p WHERE p.user_id = u.id
		         AND p.state IN ('armed','healthy','warning','grace','hold')),
		       (SELECT count(*) FROM content_bundles b WHERE b.user_id = u.id),
		       (SELECT coalesce(sum(size_bytes),0) FROM content_bundles b WHERE b.user_id = u.id)
		FROM users u
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUserRow
	for rows.Next() {
		var r AdminUserRow
		if err := rows.Scan(&r.ID, &r.Email, &r.DisplayName, &r.Status, &r.IsAdmin, &r.CreatedAt,
			&r.PolicyCount, &r.ArmedCount, &r.BundleCount, &r.BundleBytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetUserAdmin promotes/demotes by direct update. Caller must audit the change.
func SetUserAdmin(ctx context.Context, q Querier, userID uuid.UUID, isAdmin bool) error {
	tag, err := q.Exec(ctx, `UPDATE users SET is_admin = $2, updated_at = now() WHERE id = $1`, userID, isAdmin)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAdmins is used by the bootstrap promotion path: the env-var promotion
// only runs when no admin exists yet.
func CountAdmins(ctx context.Context, q Querier) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_admin = TRUE`).Scan(&n)
	return n, err
}

// RevokeAllUserSessions wipes every live session for a user — used by the
// admin force-logout action and by admin suspension.
func RevokeAllUserSessions(ctx context.Context, q Querier, userID uuid.UUID) (int64, error) {
	tag, err := q.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// TouchSessionStepUp updates step_up_at on the given session.
// Called when a user completes a fresh passkey assertion.
func TouchSessionStepUp(ctx context.Context, q Querier, sessionID uuid.UUID) error {
	_, err := q.Exec(ctx,
		`UPDATE sessions SET step_up_at = now() WHERE id = $1`, sessionID)
	return err
}

// ListAllPoliciesAdmin returns every policy with runtime next-due info, for
// the admin global policy list. Bounded by limit to protect the handler.
type AdminPolicyRow struct {
	Policy
	UserEmail string
	NextDueAt *time.Time
}

func ListAllPoliciesAdmin(ctx context.Context, q Querier, limit int) ([]AdminPolicyRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := q.Query(ctx, `
		SELECT p.id, p.user_id, p.title, p.description, p.active_version_id, p.state,
		       p.created_at, p.updated_at,
		       u.email,
		       ps.next_due_at
		FROM policies p
		JOIN users u ON u.id = p.user_id
		LEFT JOIN policy_states ps ON ps.policy_id = p.id
		ORDER BY
		  CASE p.state
		    WHEN 'triggered' THEN 0
		    WHEN 'grace'     THEN 1
		    WHEN 'hold'      THEN 2
		    WHEN 'warning'   THEN 3
		    WHEN 'healthy'   THEN 4
		    WHEN 'armed'     THEN 5
		    ELSE 9
		  END,
		  ps.next_due_at NULLS LAST,
		  p.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminPolicyRow
	for rows.Next() {
		var r AdminPolicyRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.Title, &r.Description, &r.ActiveVersionID, &r.State,
			&r.CreatedAt, &r.UpdatedAt, &r.UserEmail, &r.NextDueAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ServerSettings is the single-row admin-editable config table.
// Secrets are either plaintext (non-sensitive) or wrapped (SMTP password).
type ServerSettings struct {
	SMTPHost             *string
	SMTPPort             *int
	SMTPUsername         *string
	SMTPPasswordWrapped  []byte
	SMTPFrom             *string
	SMTPInsecureSkip     bool
	PublicBaseURL        *string
	RateLimitLoginPerMin *int
	RateLimitChkinPerMin *int
	UpdatedBy            *uuid.UUID
	UpdatedAt            time.Time
}

func GetServerSettings(ctx context.Context, q Querier) (*ServerSettings, error) {
	var s ServerSettings
	err := q.QueryRow(ctx, `
		SELECT smtp_host, smtp_port, smtp_username, smtp_password_wrapped,
		       smtp_from, smtp_insecure_skip, public_base_url,
		       rate_limit_login_per_min, rate_limit_checkin_per_min,
		       updated_by, updated_at
		FROM server_settings WHERE id = 1`).Scan(
		&s.SMTPHost, &s.SMTPPort, &s.SMTPUsername, &s.SMTPPasswordWrapped,
		&s.SMTPFrom, &s.SMTPInsecureSkip, &s.PublicBaseURL,
		&s.RateLimitLoginPerMin, &s.RateLimitChkinPerMin,
		&s.UpdatedBy, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return &ServerSettings{}, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// UpdateServerSettings writes the settings row. actor is the admin user ID.
func UpdateServerSettings(ctx context.Context, q Querier, s *ServerSettings, actor uuid.UUID) error {
	_, err := q.Exec(ctx, `
		UPDATE server_settings SET
			smtp_host = $1, smtp_port = $2, smtp_username = $3,
			smtp_password_wrapped = $4, smtp_from = $5, smtp_insecure_skip = $6,
			public_base_url = $7,
			rate_limit_login_per_min = $8, rate_limit_checkin_per_min = $9,
			updated_by = $10, updated_at = now()
		WHERE id = 1`,
		s.SMTPHost, s.SMTPPort, s.SMTPUsername, s.SMTPPasswordWrapped,
		s.SMTPFrom, s.SMTPInsecureSkip, s.PublicBaseURL,
		s.RateLimitLoginPerMin, s.RateLimitChkinPerMin, actor)
	return err
}
