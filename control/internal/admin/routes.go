package admin

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/backups"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/keyvault"
	"github.com/gcottrell/deadman/control/internal/metrics"
	"github.com/gcottrell/deadman/control/internal/notify"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
	"github.com/gcottrell/deadman/control/internal/webui"
)

// MountConfig bundles admin-route-specific dependencies that main.go holds.
type MountConfig struct {
	VaultFile *keyvault.VaultFile // nil in legacy single-key mode
	Locker    *keyvault.Locker    // nil in legacy mode
	Policy    *policy.Service
	Renderer  *webui.Renderer
	// SchedulerLastTick returns the scheduler's most recent successful tick
	// time (via the watchdog). nil means "unknown".
	SchedulerLastTick func() *time.Time
	// ServicePub is the ed25519 public key used to verify audit chain sigs
	// on the "verify chain" admin button. nil disables the button.
	ServicePub []byte
	// Storage is the live dual-writer (primary + optional backup) so the
	// storage page can show the configured endpoints/buckets. May be nil.
	Storage *storage.DualWriter
	// StartupConfig is the env-derived server config, read-only. Used by the
	// admin config page to show what the server booted with.
	StartupConfig EffectiveStartupConfig
	// MailResolver returns the currently-effective Sender (merge of env +
	// DB + unwrapped password when the vault is unlocked). Used for
	// test-send and for post-save cache invalidation.
	MailResolver *notify.Resolver

	// Metrics is the in-process registry. nil disables the metrics page.
	Metrics *metrics.Registry

	// Backups is the on-demand pg_dump manager. nil disables the backups page.
	Backups *backups.Manager
}

// EffectiveStartupConfig holds the env-derived fields the admin config page
// shows as the current live state. Populated from cfg at server start.
type EffectiveStartupConfig struct {
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPFrom          string
	SMTPInsecureSkip  bool
	SMTPPasswordIsSet bool
	PublicBaseURL     string
}

// Mount attaches the admin routes under /ui/admin/. All routes (except
// /ui/admin/reauth) require RequireAdmin.
func (d *Deps) Mount(r chi.Router, mc MountConfig) {
	// /ui/admin/reauth — accessible to any logged-in user who is an admin
	// but whose step-up is stale. Renders a page that performs a fresh
	// passkey assertion and on success calls POST /ui/admin/reauth/finish.
	r.Get("/ui/admin/reauth", func(w http.ResponseWriter, req *http.Request) {
		uid, _, err := d.Auth.Authenticate(req.Context(), req)
		if err != nil {
			http.Redirect(w, req, "/ui/login", http.StatusSeeOther)
			return
		}
		u, err := store.GetUserByID(req.Context(), d.Store.Pool, uid)
		if err != nil || !u.IsAdmin {
			http.NotFound(w, req)
			return
		}
		ctx := webui.WithUser(req.Context(), u)
		next := req.URL.Query().Get("next")
		if next == "" || !strings.HasPrefix(next, "/ui/admin") {
			next = "/ui/admin/"
		}
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_reauth", webui.PageData{
			Title: "Re-authenticate", UserEmail: u.Email,
			Admin: &webui.AdminView{NextURL: next},
		})
	})

	// POST /ui/admin/reauth/finish — rotates the session: revokes the old
	// one, mints a fresh one (which has step_up_at = now() per CreateSession),
	// and sets the new cookie. This means an attacker who exfiltrated the
	// pre-step-up cookie cannot ride the step-up the legitimate user
	// performs later — that token is dead.
	//
	// We still consider the existing session-cookie auth sufficient to
	// authorize the rotation itself. A "true" two-factor reauth would
	// require a second passkey assertion bound to a fresh challenge; that's
	// a polish pass tracked in SECURITY.md.
	r.Post("/ui/admin/reauth/finish", func(w http.ResponseWriter, req *http.Request) {
		uid, sess, err := d.Auth.Authenticate(req.Context(), req)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Revoke the current session before issuing a new one, so a stolen
		// cookie cannot continue to be used after a step-up rotation.
		if err := store.RevokeSession(req.Context(), d.Store.Pool, sess.ID); err != nil {
			d.Logger.Warn("revoke session on step-up", "err", err)
		}
		newToken, _, err := d.Auth.IssueSession(req.Context(), uid, sess.DeviceID)
		if err != nil {
			d.Logger.Warn("issue rotated session", "err", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		auth.SetSessionCookie(w, newToken, req.TLS != nil)
		next := req.FormValue("next")
		if next == "" || !strings.HasPrefix(next, "/ui/admin") {
			next = "/ui/admin/"
		}
		http.Redirect(w, req, next, http.StatusSeeOther) // #nosec G710 -- next is forced above to the literal prefix "/ui/admin", pinning a same-origin absolute path (cannot start with "//" or a scheme)
	})

	// All other admin routes require full step-up.
	r.Group(func(r chi.Router) {
		r.Use(d.RequireAdmin)

		r.Get("/ui/admin/", d.handleOverview(mc))
		r.Get("/ui/admin/users", d.handleUsers(mc))
		r.Get("/ui/admin/users/{id}", d.handleUserDetail(mc))
		r.Post("/ui/admin/users/{id}/{action}", d.handleUserAction(mc))
		r.Get("/ui/admin/policies", d.handlePolicies(mc))
		r.Post("/ui/admin/policies/{id}/{action}", d.handlePolicyAction(mc))
		r.Get("/ui/admin/vault", d.handleVault(mc))
		r.Post("/ui/admin/vault/unlock", d.handleVaultUnlock(mc))
		r.Post("/ui/admin/vault/lock", d.handleVaultLock(mc))

		r.Get("/ui/admin/ledger", d.handleLedger(mc))
		r.Post("/ui/admin/ledger/verify", d.handleLedgerVerify(mc))

		r.Get("/ui/admin/storage", d.handleStorage(mc))

		r.Get("/ui/admin/config", d.handleConfig(mc))
		r.Post("/ui/admin/config", d.handleConfigSave(mc))
		r.Post("/ui/admin/config/test-smtp", d.handleConfigTestSMTP(mc))

		r.Get("/ui/admin/metrics", d.handleMetrics(mc))

		r.Get("/ui/admin/backups", d.handleBackups(mc))
		r.Post("/ui/admin/backups/run", d.handleBackupRun(mc))
	})
}

// ---------- Backups ----------

func (d *Deps) handleBackups(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		adminU := AdminUserFromContext(req.Context())
		rows, err := store.ListBackups(req.Context(), d.Store.Pool, 100)
		if err != nil {
			d.Logger.Error("list backups", "err", err)
		}
		view := &webui.AdminView{
			BackupCanRun:   mc.Backups != nil && mc.Backups.Destination != nil,
			BackupPgDumpOK: pgDumpAvailable(),
		}
		if mc.Backups != nil {
			view.BackupKeep = mc.Backups.KeepCount
		}
		for _, b := range rows {
			r := webui.BackupRowView{
				ID:      b.ID.String(),
				Started: b.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
				Status:  b.Status,
				Bucket:  b.Bucket,
				Key:     b.Key,
			}
			if b.FinishedAt != nil {
				r.Finished = b.FinishedAt.UTC().Format("2006-01-02 15:04:05 UTC")
			}
			if b.SizeBytes != nil {
				r.SizeHuman = humanBytes(*b.SizeBytes)
			}
			if len(b.SHA256) > 0 {
				r.SHA256Hex = hex.EncodeToString(b.SHA256)
			}
			if b.Error != nil {
				r.Error = *b.Error
			}
			if b.ActorID != nil {
				r.ActorID = b.ActorID.String()
			}
			view.Backups = append(view.Backups, r)
		}
		ctx := webui.WithUser(req.Context(), adminU)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_backups", webui.PageData{
			Title: "Admin · Backups", UserEmail: adminU.Email, Admin: view,
		})
	}
}

func (d *Deps) handleBackupRun(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		adminU := AdminUserFromContext(req.Context())
		if mc.Backups == nil {
			http.Redirect(w, req, "/ui/admin/backups?flash=no_backup_mgr", http.StatusSeeOther)
			return
		}
		// Spawn in background. The admin page can be refreshed to watch
		// progress via the running/ok/failed status field.
		go func() { // #nosec G118 -- the worker must outlive the request (req ctx would kill pg_dump on redirect); bounded by the timeout below plus the single-flight guard in Manager.Run
			// Detached from the request on purpose, but not unbounded: a hung
			// pg_dump or stalled upload dies with the timeout instead of
			// leaking the goroutine, the child process, and the temp file.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			_, err := mc.Backups.Run(ctx, adminU.ID)
			if err != nil {
				d.Logger.Warn("admin backup run", "err", err)
			}
		}()
		d.AuditAdminAction(req.Context(), adminU.ID, "admin.backup_requested", "", nil, nil)
		http.Redirect(w, req, "/ui/admin/backups?flash=started", http.StatusSeeOther)
	}
}

func pgDumpAvailable() bool {
	_, err := exec.LookPath("pg_dump")
	return err == nil
}

// ---------- Metrics ----------

func (d *Deps) handleMetrics(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		view := &webui.AdminView{}
		if mc.Metrics != nil {
			s := mc.Metrics.Snapshot()
			view.MetricsSnap = &webui.MetricsSnapView{
				CapturedAt: s.CapturedAt.Format("2006-01-02 15:04:05 UTC"),
				Routes:     make([]webui.MetricsRouteView, 0, len(s.Routes)),
				Counters:   s.Counters,
				Rates:      make(map[string]webui.MetricsRateView, len(s.Rates)),
			}
			for _, r := range s.Routes {
				view.MetricsSnap.Routes = append(view.MetricsSnap.Routes, webui.MetricsRouteView{
					Route: r.Route, Count: r.Count,
					P50ms: r.P50ms, P95ms: r.P95ms, P99ms: r.P99ms, MaxMs: r.MaxMs,
				})
			}
			for k, v := range s.Rates {
				view.MetricsSnap.Rates[k] = webui.MetricsRateView{
					Last1m: v.Last1m, Last5m: v.Last5m, Last60m: v.Last60m, Total: v.Total,
				}
			}
		}
		// Release throughput from the audit table — authoritative, persists
		// across restarts.
		view.ReleaseThroughput = fetchReleaseRates(req.Context(), d)
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_metrics", webui.PageData{
			Title: "Admin · Metrics", UserEmail: admin.Email, Admin: view,
		})
	}
}

func fetchReleaseRates(ctx context.Context, d *Deps) []webui.MetricsReleaseRow {
	q := d.Store.Pool
	windows := []struct {
		label string
		sql   string
	}{
		{"1h", `now() - interval '1 hour'`},
		{"24h", `now() - interval '24 hours'`},
		{"7d", `now() - interval '7 days'`},
		{"30d", `now() - interval '30 days'`},
	}
	out := make([]webui.MetricsReleaseRow, 0, len(windows))
	for _, w := range windows {
		var n int64
		err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events
			WHERE event_type = 'release.completed' AND occurred_at >= `+w.sql).Scan(&n)
		if err != nil {
			d.Logger.Warn("release rate", "window", w.label, "err", err)
		}
		out = append(out, webui.MetricsReleaseRow{Window: w.label, Count: n})
	}
	return out
}

// ---------- Overview ----------

func (d *Deps) handleOverview(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		u := AdminUserFromContext(req.Context())
		stats, err := store.GetAdminOverview(req.Context(), d.Store.Pool)
		if err != nil {
			d.Logger.Error("admin overview", "err", err)
			stats = &store.AdminOverviewStats{}
		}
		av := &webui.AdminView{
			Overview:    stats,
			VaultStatus: vaultStatusView(mc),
		}
		if mc.SchedulerLastTick != nil {
			av.SchedulerTick = mc.SchedulerLastTick()
		}
		ctx := webui.WithUser(req.Context(), u)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_overview", webui.PageData{
			Title: "Admin · Overview", UserEmail: u.Email, Admin: av,
		})
	}
}

// ---------- Users ----------

func (d *Deps) handleUsers(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		u := AdminUserFromContext(req.Context())
		rows, err := store.ListAdminUsers(req.Context(), d.Store.Pool, 200, 0)
		if err != nil {
			d.Logger.Error("admin list users", "err", err)
		}
		ctx := webui.WithUser(req.Context(), u)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_users", webui.PageData{
			Title: "Admin · Users", UserEmail: u.Email,
			Admin: &webui.AdminView{Users: rows},
		})
	}
}

func (d *Deps) handleUserDetail(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		id, err := uuid.Parse(chi.URLParam(req, "id"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		target, err := store.GetUserByID(req.Context(), d.Store.Pool, id)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		ps, _ := store.ListUserPolicies(req.Context(), d.Store.Pool, id)
		prows := make([]webui.PolicyRow, 0, len(ps))
		for _, p := range ps {
			prows = append(prows, webui.PolicyRow{ID: p.ID, Title: p.Title, State: p.State})
		}
		bs, _ := store.ListUserBundles(req.Context(), d.Store.Pool, id)
		brows := make([]webui.BundleRow, 0, len(bs))
		for _, b := range bs {
			brows = append(brows, webui.BundleRow{
				ID: b.ID, Label: b.Label, WrapScheme: b.WrapScheme,
				SizeHuman: humanBytes(b.SizeBytes), CreatedAt: b.CreatedAt,
			})
		}
		ds, _ := store.ListUserDestinations(req.Context(), d.Store.Pool, id)
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_user_detail", webui.PageData{
			Title: "Admin · " + target.Email, UserEmail: admin.Email,
			Admin: &webui.AdminView{
				SelectedUser:  target,
				UserPolicies:  prows,
				UserBundles:   brows,
				UserDestCount: len(ds),
			},
		})
	}
}

func (d *Deps) handleUserAction(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		id, err := uuid.Parse(chi.URLParam(req, "id"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		action := chi.URLParam(req, "action")
		ctx := req.Context()
		switch action {
		case "promote":
			if admin.ID == id {
				http.Redirect(w, req, "/ui/admin/users/"+id.String()+"?flash=cannot_self", http.StatusSeeOther) // #nosec G710 -- constant local path plus uuid.Parse-validated ID; same-origin only
				return
			}
			if err := store.SetUserAdmin(ctx, d.Store.Pool, id, true); err != nil {
				d.Logger.Warn("promote", "err", err)
			} else {
				d.AuditAdminAction(ctx, admin.ID, "admin.promoted", "user", &id, map[string]any{"reason": "manual"})
			}
		case "demote":
			if admin.ID == id {
				http.Redirect(w, req, "/ui/admin/users/"+id.String()+"?flash=cannot_self", http.StatusSeeOther) // #nosec G710 -- constant local path plus uuid.Parse-validated ID; same-origin only
				return
			}
			if err := store.SetUserAdmin(ctx, d.Store.Pool, id, false); err != nil {
				d.Logger.Warn("demote", "err", err)
			} else {
				d.AuditAdminAction(ctx, admin.ID, "admin.demoted", "user", &id, nil)
			}
		case "force-logout":
			n, err := store.RevokeAllUserSessions(ctx, d.Store.Pool, id)
			if err != nil {
				d.Logger.Warn("force-logout", "err", err)
			} else {
				d.AuditAdminAction(ctx, admin.ID, "admin.user_force_logout", "user", &id,
					map[string]any{"sessions_revoked": n})
			}
		case "suspend-all":
			// Suspend every armed-ish policy for the user. We iterate via
			// the policy service so state transitions are audited through
			// the normal signed path.
			if mc.Policy == nil {
				break
			}
			ps, _ := store.ListUserPolicies(ctx, d.Store.Pool, id)
			count := 0
			for _, p := range ps {
				switch p.State {
				case "armed", "healthy", "warning", "grace", "hold":
					if err := mc.Policy.Suspend(ctx, id, p.ID); err != nil {
						d.Logger.Warn("admin suspend policy", "policy", p.ID, "err", err)
						continue
					}
					count++
				}
			}
			d.AuditAdminAction(ctx, admin.ID, "admin.user_suspend_all", "user", &id,
				map[string]any{"policies_suspended": count})
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		http.Redirect(w, req, "/ui/admin/users/"+id.String(), http.StatusSeeOther) // #nosec G710 -- constant local path plus uuid.Parse-validated ID; same-origin only
	}
}

// ---------- Policies (global) ----------

func (d *Deps) handlePolicies(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		rows, err := store.ListAllPoliciesAdmin(req.Context(), d.Store.Pool, 500)
		if err != nil {
			d.Logger.Error("admin policies", "err", err)
		}
		view := make([]webui.AdminPolicyRowView, 0, len(rows))
		now := time.Now().UTC()
		for _, r := range rows {
			nextDue := ""
			if r.NextDueAt != nil {
				delta := r.NextDueAt.Sub(now)
				nextDue = humanDelta(delta)
			}
			view = append(view, webui.AdminPolicyRowView{
				ID: r.ID, UserEmail: r.UserEmail, UserID: r.UserID,
				Title: r.Title, State: r.State, NextDue: nextDue,
			})
		}
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_policies", webui.PageData{
			Title: "Admin · Policies", UserEmail: admin.Email,
			Admin: &webui.AdminView{AllPolicies: view},
		})
	}
}

func (d *Deps) handlePolicyAction(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		id, err := uuid.Parse(chi.URLParam(req, "id"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		action := chi.URLParam(req, "action")
		if mc.Policy == nil {
			http.Error(w, "policy service unavailable", http.StatusServiceUnavailable)
			return
		}
		p, err := store.GetPolicy(req.Context(), d.Store.Pool, id)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		ctx := req.Context()
		var fnErr error
		switch action {
		case "suspend":
			fnErr = mc.Policy.Suspend(ctx, p.UserID, id)
		case "resume":
			fnErr = mc.Policy.Resume(ctx, p.UserID, id)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		if fnErr != nil {
			d.Logger.Warn("admin policy action", "action", action, "err", fnErr)
		} else {
			d.AuditAdminAction(ctx, admin.ID, "admin.policy_"+action, "policy", &id, nil)
		}
		http.Redirect(w, req, "/ui/admin/policies", http.StatusSeeOther)
	}
}

// ---------- Vault ----------

func vaultStatusView(mc MountConfig) *webui.VaultStatusView {
	v := &webui.VaultStatusView{}
	if mc.Locker != nil {
		v.Unlocked = mc.Locker.Unlocked()
	}
	if mc.VaultFile != nil {
		v.HasVault = true
		v.Share3FingerprintHex = hex.EncodeToString(mc.VaultFile.Share3Fingerprint)
	}
	return v
}

func (d *Deps) handleVault(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_vault", webui.PageData{
			Title: "Admin · Vault", UserEmail: admin.Email,
			Admin: &webui.AdminView{VaultStatus: vaultStatusView(mc)},
		})
	}
}

func (d *Deps) handleVaultUnlock(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		if mc.Locker == nil || mc.VaultFile == nil {
			http.Error(w, "threshold vault not configured", http.StatusBadRequest)
			return
		}
		if err := req.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		a := req.FormValue("passphrase_a")
		b := req.FormValue("passphrase_b")
		if a == "" || b == "" {
			http.Redirect(w, req, "/ui/admin/vault?flash=missing", http.StatusSeeOther)
			return
		}
		err := mc.Locker.UnlockWithPassphrases(mc.VaultFile, a, b)
		// Zero the formvalues (best-effort) — Go strings are immutable but
		// wipe the form map so they aren't reused.
		req.Form.Set("passphrase_a", "")
		req.Form.Set("passphrase_b", "")
		if err != nil {
			d.Logger.Warn("admin vault unlock failed", "err", err)
			d.AuditAdminAction(req.Context(), admin.ID, "admin.vault_unlock_failed", "", nil, nil)
			http.Redirect(w, req, "/ui/admin/vault?flash=bad_passphrase", http.StatusSeeOther)
			return
		}
		d.AuditAdminAction(req.Context(), admin.ID, "admin.vault_unlocked", "", nil, nil)
		http.Redirect(w, req, "/ui/admin/vault?flash=unlocked", http.StatusSeeOther)
	}
}

func (d *Deps) handleVaultLock(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		if mc.Locker == nil {
			http.Error(w, "threshold vault not configured", http.StatusBadRequest)
			return
		}
		mc.Locker.Lock()
		d.AuditAdminAction(req.Context(), admin.ID, "admin.vault_locked", "", nil, nil)
		http.Redirect(w, req, "/ui/admin/vault?flash=locked", http.StatusSeeOther)
	}
}

// ---------- Ledger ----------

func (d *Deps) handleLedger(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		q := req.URL.Query()
		f := audit.AdminFilter{
			EventType: strings.TrimSpace(q.Get("event_type")),
			ActorKind: strings.TrimSpace(q.Get("actor_kind")),
		}
		if s := q.Get("since"); s != "" {
			if t, err := parseLocalDT(s); err == nil {
				f.Since = &t
			}
		}
		if s := q.Get("until"); s != "" {
			if t, err := parseLocalDT(s); err == nil {
				f.Until = &t
			}
		}
		recs, err := audit.ListAll(req.Context(), d.Store.Pool, f, 300)
		if err != nil {
			d.Logger.Error("admin ledger list", "err", err)
		}
		rows := make([]webui.AuditRow, 0, len(recs))
		for _, e := range recs {
			rows = append(rows, renderAuditRow(e))
		}
		view := &webui.AdminView{
			Ledger: rows,
			LedgerFilter: webui.LedgerFilterView{
				EventType: f.EventType, ActorKind: f.ActorKind,
				Since: q.Get("since"), Until: q.Get("until"),
			},
			ChainStatus: q.Get("chain"),
		}
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_ledger", webui.PageData{
			Title: "Admin · Ledger", UserEmail: admin.Email, Admin: view,
		})
	}
}

func (d *Deps) handleLedgerVerify(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		if len(mc.ServicePub) != ed25519.PublicKeySize {
			http.Redirect(w, req, "/ui/admin/ledger?chain=no_pubkey", http.StatusSeeOther)
			return
		}
		err := audit.Verify(req.Context(), d.Store.Pool, ed25519.PublicKey(mc.ServicePub))
		result := "ok"
		if err != nil {
			result = err.Error()
		}
		d.AuditAdminAction(req.Context(), admin.ID, "admin.ledger_verify", "", nil,
			map[string]any{"result": result})
		http.Redirect(w, req, "/ui/admin/ledger?chain="+urlSafe(result), http.StatusSeeOther)
	}
}

// ---------- Storage ----------

func (d *Deps) handleStorage(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		m, err := store.GetStorageMetrics(req.Context(), d.Store.Pool)
		if err != nil {
			d.Logger.Error("admin storage metrics", "err", err)
			m = &store.StorageMetrics{}
		}
		incs, err := store.ListStorageIncidents(req.Context(), d.Store.Pool, 50)
		if err != nil {
			d.Logger.Error("admin storage incidents", "err", err)
		}
		iv := make([]webui.StorageIncidentView, 0, len(incs))
		for _, i := range incs {
			v := webui.StorageIncidentView{
				Seq: i.Seq, EventType: i.EventType,
				When: i.OccurredAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			}
			if i.SubjectID != nil {
				v.SubjectID = i.SubjectID.String()
			}
			if len(i.PayloadJSON) > 0 {
				var any interface{}
				if err := json.Unmarshal(i.PayloadJSON, &any); err == nil {
					if b, err := json.MarshalIndent(any, "", "  "); err == nil {
						v.PayloadJSON = string(b)
					}
				}
			}
			iv = append(iv, v)
		}
		var buckets []webui.StorageBucketView
		if mc.Storage != nil {
			if mc.Storage.Primary != nil {
				buckets = append(buckets, webui.StorageBucketView{
					Role: "primary", Bucket: mc.Storage.Primary.Bucket(),
				})
			}
			if mc.Storage.Backup != nil {
				buckets = append(buckets, webui.StorageBucketView{
					Role: "backup", Bucket: mc.Storage.Backup.Bucket(),
				})
			}
		}
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_storage", webui.PageData{
			Title: "Admin · Storage", UserEmail: admin.Email,
			Admin: &webui.AdminView{
				StorageMetrics:   m,
				StorageIncidents: iv,
				StorageBuckets:   buckets,
			},
		})
	}
}

// ---------- Config ----------

func (d *Deps) handleConfig(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		settings, err := store.GetServerSettings(req.Context(), d.Store.Pool)
		if err != nil {
			d.Logger.Warn("get server settings", "err", err)
			settings = &store.ServerSettings{}
		}
		eff := effectiveConfigView(mc, settings)
		ctx := webui.WithUser(req.Context(), admin)
		mc.Renderer.Render(w, req.WithContext(ctx), "admin_config", webui.PageData{
			Title: "Admin · Config", UserEmail: admin.Email,
			Admin: &webui.AdminView{
				Settings:        settings,
				ConfigEffective: eff,
			},
		})
	}
}

func (d *Deps) handleConfigSave(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		if err := req.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		s := &store.ServerSettings{}
		ss := func(k string) *string {
			v := strings.TrimSpace(req.FormValue(k))
			if v == "" {
				return nil
			}
			return &v
		}
		ii := func(k string) *int {
			v := strings.TrimSpace(req.FormValue(k))
			if v == "" {
				return nil
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil
			}
			return &n
		}
		s.SMTPHost = ss("smtp_host")
		s.SMTPPort = ii("smtp_port")
		s.SMTPUsername = ss("smtp_username")
		s.SMTPFrom = ss("smtp_from")
		s.SMTPInsecureSkip = req.FormValue("smtp_insecure_skip") == "on"
		s.PublicBaseURL = ss("public_base_url")
		s.RateLimitLoginPerMin = ii("rate_limit_login_per_min")
		s.RateLimitChkinPerMin = ii("rate_limit_checkin_per_min")

		// Preserve existing wrapped password unless:
		//   - clear_smtp_password=on: clear it (fall back to env)
		//   - smtp_password has a non-empty value: wrap it with the release
		//     pubkey (vault-wrapped; unwrap requires the vault unlocked).
		prior, err := store.GetServerSettings(req.Context(), d.Store.Pool)
		if err == nil && prior != nil {
			s.SMTPPasswordWrapped = prior.SMTPPasswordWrapped
		}
		if req.FormValue("clear_smtp_password") == "on" {
			s.SMTPPasswordWrapped = nil
		} else if pw := req.FormValue("smtp_password"); pw != "" {
			if mc.Locker == nil || mc.Locker.PublicKey() == nil {
				http.Redirect(w, req, "/ui/admin/config?flash=no_vault_pubkey", http.StatusSeeOther)
				return
			}
			wrapped, err := crypto.WrapServerSecret(mc.Locker.PublicKey(), []byte(pw))
			if err != nil {
				d.Logger.Error("wrap smtp password", "err", err)
				http.Redirect(w, req, "/ui/admin/config?flash=wrap_failed", http.StatusSeeOther)
				return
			}
			s.SMTPPasswordWrapped = wrapped
		}

		if err := store.UpdateServerSettings(req.Context(), d.Store.Pool, s, admin.ID); err != nil {
			d.Logger.Error("update server settings", "err", err)
			http.Redirect(w, req, "/ui/admin/config?flash=save_failed", http.StatusSeeOther)
			return
		}
		d.AuditAdminAction(req.Context(), admin.ID, "admin.settings_updated", "", nil,
			map[string]any{
				"smtp_host": derefStr(s.SMTPHost), "smtp_port": derefInt(s.SMTPPort),
				"smtp_from": derefStr(s.SMTPFrom), "public_base_url": derefStr(s.PublicBaseURL),
				"smtp_password_wrapped": len(s.SMTPPasswordWrapped) > 0,
			})
		// Drop the resolver's cache so the next send picks up the new values
		// immediately — no restart needed.
		if mc.MailResolver != nil {
			mc.MailResolver.Invalidate()
		}
		http.Redirect(w, req, "/ui/admin/config?flash=saved", http.StatusSeeOther)
	}
}

func (d *Deps) handleConfigTestSMTP(mc MountConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		admin := AdminUserFromContext(req.Context())
		var sender *notify.Sender
		if mc.MailResolver != nil {
			sender = mc.MailResolver.Current(req.Context())
		}
		if sender == nil {
			http.Redirect(w, req, "/ui/admin/config?flash=no_mailer", http.StatusSeeOther)
			return
		}
		to := strings.TrimSpace(req.FormValue("to"))
		if to == "" {
			to = admin.Email
		}
		err := sender.Send([]string{to},
			"Deadman · SMTP test",
			"This is a test message from the Deadman admin panel.\n"+
				"If you received this, SMTP is correctly configured.\n")
		result := "ok"
		if err != nil {
			result = err.Error()
		}
		d.AuditAdminAction(req.Context(), admin.ID, "admin.smtp_test_sent", "", nil,
			map[string]any{"to": to, "result": result})
		http.Redirect(w, req, "/ui/admin/config?flash=smtp_"+urlSafe(result), http.StatusSeeOther)
	}
}

func effectiveConfigView(mc MountConfig, s *store.ServerSettings) *webui.EffectiveConfigView {
	e := mc.StartupConfig
	v := &webui.EffectiveConfigView{
		SMTPHost: e.SMTPHost, SMTPPort: e.SMTPPort,
		SMTPUsername: e.SMTPUsername, SMTPFrom: e.SMTPFrom,
		SMTPInsecureSkip: e.SMTPInsecureSkip,
		PublicBaseURL:    e.PublicBaseURL,
	}
	if mc.MailResolver != nil {
		v.MailerEnabled = mc.MailResolver.Current(context.Background()) != nil
	}
	switch {
	case len(s.SMTPPasswordWrapped) > 0:
		if mc.Locker != nil && mc.Locker.Unlocked() {
			v.SMTPPasswordMask = "(stored in vault, available)"
		} else {
			v.SMTPPasswordMask = "(stored in vault, unlock required)"
		}
	case e.SMTPPasswordIsSet:
		v.SMTPPasswordMask = "(set via env)"
	default:
		v.SMTPPasswordMask = "(unset)"
	}
	// Has the DB diverged from env? If so, surface restart-required warning.
	v.RestartRequired = (s.SMTPHost != nil && *s.SMTPHost != e.SMTPHost) ||
		(s.SMTPPort != nil && *s.SMTPPort != e.SMTPPort) ||
		(s.SMTPFrom != nil && *s.SMTPFrom != e.SMTPFrom) ||
		(s.PublicBaseURL != nil && *s.PublicBaseURL != e.PublicBaseURL)
	return v
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// parseLocalDT parses the HTML5 datetime-local form value as UTC. Accepts
// "2006-01-02T15:04" and "2006-01-02".
func parseLocalDT(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02T15:04", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("bad datetime: %q", s)
}

// urlSafe truncates and url-encodes a short diagnostic string for use in
// redirect query params. We only need it readable in logs.
func urlSafe(s string) string {
	if len(s) > 120 {
		s = s[:120]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

// renderAuditRow mirrors webui.renderAuditRow (internal to that package).
// We keep a small copy here rather than exposing internals.
func renderAuditRow(e audit.Record) webui.AuditRow {
	row := webui.AuditRow{
		Seq:            e.Seq,
		EventID:        e.ID.String(),
		EventType:      e.EventType,
		WhenHuman:      e.OccurredAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		PrevHashHex:    hex.EncodeToString(e.PrevHash[:]),
		PayloadHashHex: hex.EncodeToString(e.PayloadHash[:]),
	}
	switch e.ActorKind {
	case audit.ActorUser:
		if e.ActorID != nil {
			row.ActorSummary = "user " + e.ActorID.String()[:8]
		} else {
			row.ActorSummary = "user"
		}
	case audit.ActorService:
		row.ActorSummary = "service"
	case audit.ActorSystem:
		row.ActorSummary = "system"
	case audit.ActorDevice:
		row.ActorSummary = "device"
	case audit.ActorDelegate:
		row.ActorSummary = "delegate"
	default:
		row.ActorSummary = string(e.ActorKind)
	}
	if e.SubjectKind != nil && e.SubjectID != nil {
		row.SubjectSummary = *e.SubjectKind + " " + e.SubjectID.String()[:8]
	}
	if len(e.Payload) > 0 && string(e.Payload) != "null" {
		var v interface{}
		if err := json.Unmarshal(e.Payload, &v); err == nil {
			if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
				row.PayloadPretty = string(pretty)
			}
		}
	}
	return row
}

// ---------- helpers ----------

func humanBytes(n int64) string {
	const k = 1024
	if n < k {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / k
	i := 0
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, units[i])
	}
	return fmt.Sprintf("%.0f %s", v, units[i])
}

func humanDelta(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	days := int64(d / (24 * time.Hour))
	h := int64(d/time.Hour) % 24
	m := int64(d/time.Minute) % 60
	pref := ""
	if neg {
		pref = "overdue "
	}
	switch {
	case days > 0:
		return fmt.Sprintf("%s%dd %dh", pref, days, h)
	case h > 0:
		return fmt.Sprintf("%s%dh %dm", pref, h, m)
	default:
		return fmt.Sprintf("%s%dm", pref, m)
	}
}
