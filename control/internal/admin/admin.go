// Package admin provides the server-side surface for the operator admin
// panel: middleware that gates /ui/admin routes on (1) an authenticated
// session belonging to an is_admin=true user, and (2) a "step-up" fresh
// passkey assertion within the last StepUpWindow.
//
// The admin panel deliberately does NOT expose any user ciphertext, passkey
// private material, destination auth tokens in cleartext, vault passphrases,
// or the offline recovery share. It exposes metadata (counts, sizes, state,
// audit trail) and a small set of operator actions. Every admin action that
// mutates state MUST write a corresponding entry to the hash-chained audit
// ledger with ActorUser + the admin's user ID.
package admin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/store"
	"github.com/gcottrell/deadman/control/internal/webui"
)

// StepUpWindow is how long after a passkey assertion the user is considered
// "re-authenticated" for admin-privileged actions. Short enough to limit a
// walk-away-from-laptop attacker, long enough to be usable.
const StepUpWindow = 5 * time.Minute

// Deps bundles what admin routes need from the rest of the server.
type Deps struct {
	Logger  *slog.Logger
	Store   *store.Store
	Auth    *auth.Service
	Ledger  *audit.Ledger
	DevMode bool
}

// ctxKey is unique to this package.
type ctxKey int

const ctxKeyAdminUser ctxKey = 0

// AdminUserFromContext returns the admin user for the current request, if any.
func AdminUserFromContext(ctx context.Context) *store.User {
	u, _ := ctx.Value(ctxKeyAdminUser).(*store.User)
	return u
}

// RequireAdmin is middleware that:
//  1. Requires an authenticated session (redirects to /ui/login otherwise).
//  2. Requires user.is_admin = true (404s otherwise — we do not reveal the
//     existence of the admin surface to non-admins).
//  3. Requires session.step_up_at within StepUpWindow (redirects to
//     /ui/admin/reauth otherwise; after reauth the user is sent back here).
//
// On success, the store.User is attached to the request context.
func (d *Deps) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, sess, err := d.Auth.Authenticate(r.Context(), r)
		if err != nil {
			http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			return
		}
		u, err := store.GetUserByID(r.Context(), d.Store.Pool, uid)
		if err != nil {
			http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			return
		}
		if !u.IsAdmin {
			// Do NOT leak the admin surface. 404.
			http.NotFound(w, r)
			return
		}
		if sess.StepUpAt == nil || time.Since(*sess.StepUpAt) > StepUpWindow {
			// Preserve return URL via query string, opaque to user.
			next := r.URL.Path
			if r.URL.RawQuery != "" {
				next += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/ui/admin/reauth?next="+next, http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyAdminUser, u)
		// Stash session so downstream rendering picks up the CSRF token
		// without each handler having to thread it.
		ctx = webui.WithSession(ctx, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuditAdminAction is a convenience for admin handlers: emits an audit event
// with the admin user as actor. eventType should be dotted ("admin.X").
func (d *Deps) AuditAdminAction(ctx context.Context, actor uuid.UUID, eventType string,
	subjectKind string, subjectID *uuid.UUID, payload map[string]any) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["admin_user_id"] = actor.String()
	ev := audit.Event{
		ActorKind: audit.ActorUser,
		ActorID:   &actor,
		EventType: eventType,
		Payload:   payload,
	}
	if subjectKind != "" {
		ev.SubjectKind = subjectKind
		ev.SubjectID = subjectID
	}
	if _, err := d.Ledger.Append(ctx, d.Store, ev); err != nil {
		d.Logger.Warn("admin audit append failed", "event_type", eventType, "err", err)
	}
}
