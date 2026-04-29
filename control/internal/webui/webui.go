// Package webui serves the server-rendered HTML UI.
//
// Design: strict CSP, no third-party origins, no transpiler, no JS framework.
// The only client JS is the passkey ceremony, loaded from same-origin with a
// per-request CSP nonce.
package webui

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/ratelimit"
	"github.com/gcottrell/deadman/control/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// nonceCtxKey is the context key carrying the per-request CSP nonce.
// The security middleware (package httpapi) writes the same key with a
// string type; we read it here via the exported helper below.
type nonceKeyT struct{}

var nonceKey nonceKeyT

// NonceKey is the exported context key so httpapi can stuff the nonce in.
func NonceKey() any { return nonceKey }

func nonceFrom(ctx context.Context) string {
	s, _ := ctx.Value(nonceKey).(string)
	return s
}

// Renderer holds parsed templates.
type Renderer struct {
	tmpls map[string]*template.Template
}

// NewRenderer parses every page template with the shared layout.
func NewRenderer() (*Renderer, error) {
	layoutBytes, err := fs.ReadFile(templatesFS, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	pages := []string{
		"home", "register", "login", "dashboard",
		"policy_new", "policy_detail", "bundle_new", "destinations",
		"help", "welcome", "audit", "account", "totp_setup",
		"admin_overview", "admin_users", "admin_user_detail",
		"admin_policies", "admin_vault", "admin_reauth",
		"admin_ledger", "admin_storage", "admin_config",
		"admin_metrics", "admin_backups",
	}
	r := &Renderer{tmpls: make(map[string]*template.Template, len(pages))}
	for _, p := range pages {
		pageBytes, err := fs.ReadFile(templatesFS, "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		t := template.New(p)
		if _, err := t.Parse(string(layoutBytes)); err != nil {
			return nil, err
		}
		if _, err := t.Parse(string(pageBytes)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		r.tmpls[p] = t
	}
	return r, nil
}

// PageData is the common template context.
type PageData struct {
	Title        string
	Nonce        string
	CSRFToken    string // base64url-encoded; rendered as hidden form input
	UserEmail    string
	IsAdmin      bool
	Flash        string
	FlashKind    string
	DevMode      bool
	Policies     []PolicyRow
	Bundles      []BundleRow
	Destinations []DestinationRow
	Policy       *store.Policy
	Runtime      *store.PolicyState

	// Dashboard countdown fields.
	AnyArmed          bool
	WorstState        string // worst = closest to triggered
	SoonestDueUnix    int64
	CountdownHeadline string
	CountdownDetail   string

	// First-run guided setup (shown on dashboard until first policy is armed).
	ShowSetup     bool
	SetupProgress int
	SetupSteps    []SetupStep

	// Audit page.
	AuditEvents []AuditRow

	// Policy-detail extras.
	TokenWarnings []string

	// Admin pages.
	Admin *AdminView

	// TOTP enrollment view (totp_setup template).
	TOTPSecret    string
	TOTPURI       string
	RecoveryCodes []string
}

// AdminView bundles fields for admin pages so PageData stays manageable.
type AdminView struct {
	Overview       *store.AdminOverviewStats
	Users          []store.AdminUserRow
	SelectedUser   *store.User
	UserPolicies   []PolicyRow
	UserBundles    []BundleRow
	UserDestCount  int
	AllPolicies    []AdminPolicyRowView
	VaultStatus    *VaultStatusView
	NextURL        string
	Settings       *store.ServerSettings
	SchedulerTick  *time.Time

	// Ledger page.
	Ledger      []AuditRow
	LedgerFilter LedgerFilterView
	ChainStatus string // "" | "ok" | error description

	// Storage page.
	StorageMetrics   *store.StorageMetrics
	StorageIncidents []StorageIncidentView
	StorageBuckets   []StorageBucketView

	// Config page.
	ConfigEffective *EffectiveConfigView

	// Metrics page.
	MetricsSnap       *MetricsSnapView
	ReleaseThroughput []MetricsReleaseRow

	// Backups page.
	Backups           []BackupRowView
	BackupKeep        int
	BackupCanRun      bool
	BackupPgDumpOK    bool
}

// BackupRowView renders one admin_backups row.
type BackupRowView struct {
	ID         string
	Started    string
	Finished   string
	SizeHuman  string
	SHA256Hex  string
	Status     string
	Error      string
	Bucket     string
	Key        string
	ActorID    string
}

// MetricsSnapView is the admin-rendered copy of metrics.Snapshot.
type MetricsSnapView struct {
	CapturedAt string
	Routes     []MetricsRouteView
	Counters   map[string]int64
	Rates      map[string]MetricsRateView
}

// MetricsRouteView is per-route latency summary for rendering.
type MetricsRouteView struct {
	Route string
	Count int64
	P50ms int64
	P95ms int64
	P99ms int64
	MaxMs int64
}

// MetricsRateView is event-count-over-windows for rendering.
type MetricsRateView struct {
	Last1m  int64
	Last5m  int64
	Last60m int64
	Total   int64
}

// MetricsReleaseRow is a throughput number over a named window.
type MetricsReleaseRow struct {
	Window string
	Count  int64
}

// LedgerFilterView preserves selected filter values in the form.
type LedgerFilterView struct {
	EventType string
	ActorKind string
	Since     string // RFC3339 input
	Until     string
}

// StorageIncidentView renders an incident row for the admin storage page.
type StorageIncidentView struct {
	Seq         int64
	EventType   string
	When        string
	SubjectID   string
	PayloadJSON string
}

// StorageBucketView is the live side of the storage page: endpoint + bucket
// for primary and backup, reported straight from the running DualWriter.
type StorageBucketView struct {
	Role     string
	Endpoint string
	Bucket   string
}

// EffectiveConfigView is what the admin config page shows: a merge of the
// env-derived startup config and the DB row (DB overrides env when set).
// Secrets are never rendered in full.
type EffectiveConfigView struct {
	SMTPHost         string
	SMTPPort         int
	SMTPUsername     string
	SMTPPasswordMask string // "(set via env)" or "(unset)"
	SMTPFrom         string
	SMTPInsecureSkip bool
	PublicBaseURL    string
	MailerEnabled    bool
	RestartRequired  bool
}

// AdminPolicyRowView is a view wrapper to include human text.
type AdminPolicyRowView struct {
	ID        uuid.UUID
	UserEmail string
	UserID    uuid.UUID
	Title     string
	State     string
	NextDue   string
}

// VaultStatusView is the operator-facing vault state snapshot.
type VaultStatusView struct {
	Unlocked            bool
	HasVault            bool
	Share3FingerprintHex string
}

// AuditRow is a rendered audit event for the user-visible log.
type AuditRow struct {
	Seq            int64
	EventID        string
	EventType      string
	WhenHuman      string
	ActorSummary   string
	SubjectSummary string
	PrevHashHex    string
	PayloadHashHex string
	PayloadPretty  string
}

// SetupStep describes one step in the first-run guided flow.
type SetupStep struct {
	Num     int
	Title   string
	Blurb   string
	CTA     string
	CTAText string
	Status  string // "done" | "active" | "pending"
	Subtext string
}

// DestinationRow is a compact view.
type DestinationRow struct {
	ID                uuid.UUID
	Kind              string
	Label             string
	ConfigSummary     string
	CreatedAt         time.Time
	Attached          bool // policy-edit form
	TokenExpiresHuman string
	TokenExpirySoon   bool
}

// BundleRow is a compact view for the dashboard.
type BundleRow struct {
	ID         uuid.UUID
	Label      string
	WrapScheme string
	SizeHuman  string
	CreatedAt  time.Time
	Attached   bool // policy-edit form
}

// PolicyRow is a compact view for the dashboard list.
type PolicyRow struct {
	ID        uuid.UUID
	Title     string
	State     string
	NextDueAt *time.Time
}

func (r *Renderer) render(w http.ResponseWriter, req *http.Request, page string, data PageData) {
	data.Nonce = nonceFrom(req.Context())
	// Auto-populate IsAdmin from the request's authed user, so handlers
	// don't have to thread it.
	if u := userFrom(req.Context()); u != nil && u.IsAdmin {
		data.IsAdmin = true
	}
	// Auto-populate CSRFToken from the session cookie (looked up here, not
	// threaded through every handler). Forms render it as a hidden input.
	if sess := sessionFrom(req.Context()); sess != nil {
		data.CSRFToken = base64.RawURLEncoding.EncodeToString(sess.CSRFToken)
	}
	t, ok := r.tmpls[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "layout", data)
}

type userCtxKeyT struct{}
type sessionCtxKeyT struct{}

var userKey userCtxKeyT
var sessionKey sessionCtxKeyT

func withUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func withSession(ctx context.Context, s *store.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func userFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userKey).(*store.User)
	return u
}

func sessionFrom(ctx context.Context) *store.Session {
	s, _ := ctx.Value(sessionKey).(*store.Session)
	return s
}

// WithUser attaches a user to a request context using the webui's internal
// key, so the layout template's nav can pick up IsAdmin / email. Exported so
// the admin package can share the same rendering pipeline.
func WithUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// WithSession attaches a session to a request context so the renderer can
// pick up CSRFToken. Exported for the admin package.
func WithSession(ctx context.Context, s *store.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// Render exposes the internal renderer for foreign packages (admin) that
// want to reuse the shared layout/nonce/CSP pipeline.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, page string, data PageData) {
	r.render(w, req, page, data)
}

// MountConfig configures the web UI at mount time.
type MountConfig struct {
	DevMode             bool
	BootstrapAdminEmail string
	RPDisplayName       string
}

// Mount attaches the web UI. Calls MountWithConfig with zero-value config.
func Mount(r chi.Router, logger *slog.Logger, s *store.Store, authSvc *auth.Service, polSvc *policy.Service, rend *Renderer) error {
	return MountWithConfig(r, logger, s, authSvc, polSvc, rend, MountConfig{})
}

// MountWithConfig is the full-signature mount.
func MountWithConfig(r chi.Router, logger *slog.Logger, s *store.Store, authSvc *auth.Service, polSvc *policy.Service, rend *Renderer, cfg MountConfig) error {
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	r.Handle("/ui/static/*", http.StripPrefix("/ui/static/", http.FileServer(http.FS(static))))

	authH := &authHandlers{
		logger:              logger,
		store:               s,
		auth:                authSvc,
		rend:                rend,
		pending:             newPendingStore(),
		bootstrapAdminEmail: cfg.BootstrapAdminEmail,
		rpDisplayName:       cfg.RPDisplayName,
	}

	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/ui/", http.StatusSeeOther)
	})

	r.Get("/ui/", func(w http.ResponseWriter, req *http.Request) {
		if _, sess, err := authSvc.Authenticate(req.Context(), req); err == nil && sess != nil {
			_ = sess
			http.Redirect(w, req, "/ui/dashboard", http.StatusSeeOther)
			return
		}
		rend.render(w, req, "home", PageData{Title: "Home"})
	})
	r.Get("/ui/register", func(w http.ResponseWriter, req *http.Request) {
		rend.render(w, req, "register", PageData{Title: "Create account"})
	})
	r.Post("/ui/register", authH.postRegister)
	r.Post("/ui/login", authH.postLogin)
	r.Get("/ui/help", func(w http.ResponseWriter, req *http.Request) {
		// Surface the logged-in email + session if any, so the nav and the
		// logout form's CSRF token render consistently.
		ctx := req.Context()
		var email string
		if uid, sess, err := authSvc.Authenticate(ctx, req); err == nil {
			if u, err := store.GetUserByID(ctx, s.Pool, uid); err == nil {
				email = u.Email
				ctx = withUser(ctx, u)
				ctx = withSession(ctx, sess)
			}
		}
		rend.render(w, req.WithContext(ctx), "help", PageData{Title: "Help & Safety", UserEmail: email})
	})
	r.Get("/ui/login", func(w http.ResponseWriter, req *http.Request) {
		rend.render(w, req, "login", PageData{Title: "Log in"})
	})
	r.Post("/ui/logout", func(w http.ResponseWriter, req *http.Request) {
		if _, sess, err := authSvc.Authenticate(req.Context(), req); err == nil && sess != nil {
			_ = store.RevokeSession(req.Context(), s.Pool, sess.ID)
		}
		http.SetCookie(w, &http.Cookie{
			Name: auth.SessionCookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, req, "/ui/", http.StatusSeeOther)
	})

	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				uid, sess, err := authSvc.Authenticate(req.Context(), req)
				if err != nil {
					http.Redirect(w, req, "/ui/login", http.StatusSeeOther)
					return
				}
				u, err := store.GetUserByID(req.Context(), s.Pool, uid)
				if err != nil {
					http.Redirect(w, req, "/ui/login", http.StatusSeeOther)
					return
				}
				ctx := withUser(req.Context(), u)
				ctx = withSession(ctx, sess)
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})

		r.Get("/ui/welcome", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			rend.render(w, req, "welcome", PageData{Title: "Welcome", UserEmail: u.Email})
		})

		r.Get("/ui/auth/totp/setup", authH.getTOTPSetup)
		r.Post("/ui/auth/totp/setup", authH.postTOTPSetup)

		// Account: per-user self-service export + delete.
		// Export emits a JSON dump of every metadata record tied to the
		// current user (no ciphertext, no passkey privates — there are
		// none server-side). Delete cascades through the FK relationships,
		// emits an audit event, and revokes the session.
		r.Get("/ui/account", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			rend.render(w, req, "account", PageData{Title: "Your account", UserEmail: u.Email})
		})
		r.Get("/ui/account/export.json", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			out, err := buildUserExport(req.Context(), s, u.ID)
			if err != nil {
				logger.Error("user export", "err", err)
				http.Error(w, "export failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="deadman-account-export.json"`)
			_, _ = w.Write(out)
		})
		r.Post("/ui/account/delete", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			sess := sessionFrom(req.Context())
			// Require a fresh step-up: deletion is irreversible. If the
			// session was issued more than 5 minutes ago, send the user
			// to the reauth page first.
			if sess == nil || sess.StepUpAt == nil || time.Since(*sess.StepUpAt) > 5*time.Minute {
				http.Redirect(w, req, "/ui/admin/reauth?next=/ui/account", http.StatusSeeOther)
				return
			}
			confirm := strings.TrimSpace(req.FormValue("confirm_email"))
			if confirm != u.Email {
				rend.render(w, req, "account", PageData{
					Title: "Your account", UserEmail: u.Email,
					Flash: "Email confirmation did not match. No changes made.",
					FlashKind: "error",
				})
				return
			}
			err := s.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
				if _, err := authSvc.Ledger().AppendTx(ctx, q, audit.Event{
					ActorKind:   audit.ActorUser,
					ActorID:     &u.ID,
					EventType:   "account.deleted",
					SubjectKind: "user",
					SubjectID:   &u.ID,
					Payload:     map[string]any{"email": u.Email, "self_service": true},
				}); err != nil {
					return err
				}
				return store.DeleteUser(ctx, q, u.ID)
			})
			if err != nil {
				logger.Error("account delete", "err", err)
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
			// Clear the cookie and bounce to home.
			http.SetCookie(w, &http.Cookie{
				Name: auth.SessionCookieName, Value: "", Path: "/", MaxAge: -1,
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, req, "/ui/?deleted=1", http.StatusSeeOther)
		})

		r.Get("/ui/audit", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			events, err := audit.ListForUser(req.Context(), s.Pool, u.ID, 200)
			if err != nil {
				logger.Error("audit list", "err", err)
			}
			rows := make([]AuditRow, 0, len(events))
			for _, e := range events {
				rows = append(rows, renderAuditRow(e))
			}
			rend.render(w, req, "audit", PageData{Title: "Activity log", UserEmail: u.Email, AuditEvents: rows})
		})

		r.Get("/ui/dashboard", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			ps, _ := store.ListUserPolicies(req.Context(), s.Pool, u.ID)
			// Brand-new account with no activity yet? Bounce once to the
			// welcome page. The "seen=1" query param prevents a loop if
			// the user ignores it and returns to the dashboard manually.
			if len(ps) == 0 && req.URL.Query().Get("seen") == "" {
				bs0, _ := store.ListUserBundles(req.Context(), s.Pool, u.ID)
				if len(bs0) == 0 {
					http.Redirect(w, req, "/ui/welcome", http.StatusSeeOther)
					return
				}
			}
			rows := make([]PolicyRow, 0, len(ps))
			for _, p := range ps {
				row := PolicyRow{ID: p.ID, Title: p.Title, State: p.State}
				if rt, err := store.GetPolicyState(req.Context(), s.Pool, p.ID); err == nil && rt != nil {
					row.NextDueAt = rt.NextDueAt
				}
				rows = append(rows, row)
			}
			bs, _ := store.ListUserBundles(req.Context(), s.Pool, u.ID)
			brows := make([]BundleRow, 0, len(bs))
			for _, b := range bs {
				brows = append(brows, BundleRow{
					ID:         b.ID,
					Label:      b.Label,
					WrapScheme: b.WrapScheme,
					SizeHuman:  humanBytes(b.SizeBytes),
					CreatedAt:  b.CreatedAt,
				})
			}
			ds, _ := store.ListUserDestinations(req.Context(), s.Pool, u.ID)
			pd := PageData{Title: "Dashboard", UserEmail: u.Email, Policies: rows, Bundles: brows}
			fillCountdown(&pd, ps)
			fillSetup(&pd, bs, ds, ps)
			// Second pass: find soonest next_due_at among armed policies
			// using the rows we already built.
			var soonest *time.Time
			for _, r := range rows {
				if _, ok := stateRank[r.State]; !ok || r.NextDueAt == nil {
					continue
				}
				if soonest == nil || r.NextDueAt.Before(*soonest) {
					t := *r.NextDueAt
					soonest = &t
				}
			}
			if soonest != nil {
				pd.SoonestDueUnix = soonest.Unix()
				now := time.Now().UTC()
				delta := soonest.Sub(now)
				pd.CountdownHeadline = formatDelta(delta)
				if delta < 0 {
					pd.CountdownDetail = "Check in now to reset the timer. If the grace window also passes, your policy will release."
				} else {
					pd.CountdownDetail = "Time until next check-in is required. Check in any time to reset."
				}
			}
			rend.render(w, req, "dashboard", pd)
		})

		r.Get("/ui/policies/new", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			bs, _ := store.ListUserBundles(req.Context(), s.Pool, u.ID)
			brows := make([]BundleRow, 0, len(bs))
			for _, b := range bs {
				brows = append(brows, BundleRow{
					ID: b.ID, Label: b.Label, SizeHuman: humanBytes(b.SizeBytes),
				})
			}
			ds, _ := store.ListUserDestinations(req.Context(), s.Pool, u.ID)
			drows := make([]DestinationRow, 0, len(ds))
			for _, d := range ds {
				drows = append(drows, DestinationRow{
					ID: d.ID, Kind: d.Kind, Label: d.Label,
					ConfigSummary: summarizeConfig(d.Kind, d.Config),
				})
			}
			rend.render(w, req, "policy_new", PageData{
				Title: "New policy", UserEmail: u.Email,
				Bundles: brows, Destinations: drows,
			})
		})

		r.Get("/ui/bundles/new", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			rend.render(w, req, "bundle_new", PageData{Title: "New bundle", UserEmail: u.Email})
		})

		r.Get("/ui/destinations", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			ds, _ := store.ListUserDestinations(req.Context(), s.Pool, u.ID)
			rows := make([]DestinationRow, 0, len(ds))
			soonCutoff := time.Now().UTC().Add(30 * 24 * time.Hour)
			for _, d := range ds {
				row := DestinationRow{
					ID: d.ID, Kind: d.Kind, Label: d.Label,
					ConfigSummary: summarizeConfig(d.Kind, d.Config),
					CreatedAt:     d.CreatedAt,
				}
				if d.TokenExpiresAt != nil {
					row.TokenExpiresHuman = d.TokenExpiresAt.UTC().Format("2006-01-02")
					row.TokenExpirySoon = d.TokenExpiresAt.Before(soonCutoff)
				}
				rows = append(rows, row)
			}
			rend.render(w, req, "destinations", PageData{
				Title: "Destinations", UserEmail: u.Email, Destinations: rows,
			})
		})

		r.Post("/ui/destinations/new", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			if err := req.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			kind := req.Form.Get("kind")
			label := strings.TrimSpace(req.Form.Get("label"))
			cfg := map[string]any{}
			switch kind {
			case "public_page":
				// nothing extra required
			case "webhook":
				url := strings.TrimSpace(req.Form.Get("webhook_url"))
				if url == "" {
					http.Redirect(w, req, "/ui/destinations", http.StatusSeeOther)
					return
				}
				cfg["url"] = url
			case "email":
				rawR := req.Form.Get("email_recipients")
				var rec []string
				for _, line := range strings.Split(rawR, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						rec = append(rec, line)
					}
				}
				if len(rec) == 0 {
					http.Redirect(w, req, "/ui/destinations", http.StatusSeeOther)
					return
				}
				cfg["recipients"] = rec
				if subj := strings.TrimSpace(req.Form.Get("email_subject")); subj != "" {
					cfg["subject"] = subj
				}
			default:
				http.Error(w, "unknown kind", http.StatusBadRequest)
				return
			}
			cfgJSON, _ := marshalJSON(cfg)
			_, err := store.CreateDestination(req.Context(), s.Pool, &store.Destination{
				UserID: u.ID, Kind: kind, Label: label, Config: cfgJSON,
			})
			if err != nil {
				logger.Error("create destination", "err", err)
			}
			http.Redirect(w, req, "/ui/destinations", http.StatusSeeOther)
		})

		r.Post("/ui/destinations/{id}/revoke", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			d, err := store.GetDestination(req.Context(), s.Pool, id)
			if err == nil && d.UserID == u.ID {
				_ = store.RevokeDestination(req.Context(), s.Pool, id)
			}
			http.Redirect(w, req, "/ui/destinations", http.StatusSeeOther)
		})

		// Browser check-in: session-authenticated one-click. Resets deadlines
		// on every armed policy owned by the user. Audit actor is the user;
		// no device signature. Less robust than the native-app signed-nonce
		// protocol, but practical for whistle-blowers without a phone.
		browserCheckin := ratelimit.New(1, 20, 10*time.Minute)
		userKey := func(r *http.Request) string {
			if u := userFrom(r.Context()); u != nil {
				return "user:" + u.ID.String()
			}
			return ""
		}
		r.With(ratelimit.Middleware(browserCheckin, userKey)).Post("/ui/checkin", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			n, err := polSvc.CheckInAllArmed(req.Context(), u.ID, nil)
			if err != nil {
				logger.Error("browser checkin", "err", err)
			}
			_ = n
			http.Redirect(w, req, "/ui/dashboard", http.StatusSeeOther)
		})

		r.Post("/ui/policies/new", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			if err := req.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			interval := atoiDefault(req.Form.Get("interval_days"), 14)
			grace := atoiDefault(req.Form.Get("grace_period_hours"), 72)
			if grace < 24 {
				rend.render(w, req, "policy_new", PageData{
					Title: "New policy", UserEmail: u.Email,
					Flash: "Grace period must be at least 24 hours.", FlashKind: "error",
				})
				return
			}
			hold := atoiDefault(req.Form.Get("hold_period_hours"), 0)
			mode := req.Form.Get("release_mode")
			if mode == "" {
				mode = "private"
			}
			if mode == "full_public" {
				mode = "limited_public"
			}
			// Multi-value form parsing for bundle_ids and destination_ids.
			parseIDs := func(key string) []uuid.UUID {
				raw := req.Form[key]
				out := make([]uuid.UUID, 0, len(raw))
				for _, s := range raw {
					if id, err := uuid.Parse(s); err == nil {
						out = append(out, id)
					}
				}
				return out
			}
			p, _, err := polSvc.Create(req.Context(), policy.CreateInput{
				UserID:           u.ID,
				Title:            strings.TrimSpace(req.Form.Get("title")),
				Description:      strings.TrimSpace(req.Form.Get("description")),
				IntervalDays:     interval,
				GracePeriodHours: grace,
				HoldPeriodHours:  hold,
				ReleaseMode:      mode,
				BundleIDs:        parseIDs("bundle_ids"),
				DestinationIDs:   parseIDs("destination_ids"),
				UserSignature:    make([]byte, 64),
			})
			if err != nil {
				logger.Error("policy create", "err", err)
				rend.render(w, req, "policy_new", PageData{
					Title: "New policy", UserEmail: u.Email,
					Flash: "Could not create policy: " + err.Error(), FlashKind: "error",
				})
				return
			}
			http.Redirect(w, req, "/ui/policies/"+p.ID.String(), http.StatusSeeOther)
		})

		r.Get("/ui/policies/{id}", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			p, err := store.GetPolicy(req.Context(), s.Pool, id)
			if err != nil || p.UserID != u.ID {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			rt, _ := store.GetPolicyState(req.Context(), s.Pool, id)

			// Load active version so we can pre-check attached bundles/destinations.
			pv, _ := store.GetActivePolicyVersion(req.Context(), s.Pool, id)
			attachedBundle := map[uuid.UUID]bool{}
			attachedDest := map[uuid.UUID]bool{}
			if pv != nil {
				for _, b := range pv.ContentBundleIDs {
					attachedBundle[b] = true
				}
				for _, d := range pv.DestinationIDs {
					attachedDest[d] = true
				}
			}

			// Build attachment lists only when policy is editable.
			var bundleRows []BundleRow
			var destRows []DestinationRow
			if p.State == "draft" || p.State == "suspended" {
				bs, _ := store.ListUserBundles(req.Context(), s.Pool, u.ID)
				for _, b := range bs {
					bundleRows = append(bundleRows, BundleRow{
						ID: b.ID, Label: b.Label,
						SizeHuman: humanBytes(b.SizeBytes),
						Attached:  attachedBundle[b.ID],
					})
				}
				ds, _ := store.ListUserDestinations(req.Context(), s.Pool, u.ID)
				for _, d := range ds {
					destRows = append(destRows, DestinationRow{
						ID: d.ID, Kind: d.Kind, Label: d.Label,
						ConfigSummary: summarizeConfig(d.Kind, d.Config),
						Attached:      attachedDest[d.ID],
					})
				}
			}

			// Token-expiry warnings: any attached destination whose
			// token_expires_at is within 30 days.
			var tokenWarns []string
			if pv != nil {
				horizon := time.Now().UTC().Add(30 * 24 * time.Hour)
				for _, did := range pv.DestinationIDs {
					d, err := store.GetDestination(req.Context(), s.Pool, did)
					if err != nil || d.TokenExpiresAt == nil {
						continue
					}
					if d.TokenExpiresAt.Before(horizon) {
						tokenWarns = append(tokenWarns,
							fmt.Sprintf("%s (%s) expires %s", d.Label, d.Kind,
								d.TokenExpiresAt.UTC().Format("2006-01-02")))
					}
				}
			}

			rend.render(w, req, "policy_detail", PageData{
				Title: p.Title, UserEmail: u.Email, Policy: p, Runtime: rt,
				DevMode: cfg.DevMode,
				Bundles: bundleRows, Destinations: destRows,
				TokenWarnings: tokenWarns,
			})
		})

		r.Post("/ui/policies/{id}/attachments", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			if err := req.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			parseIDs := func(key string) []uuid.UUID {
				raw := req.Form[key]
				out := make([]uuid.UUID, 0, len(raw))
				for _, s := range raw {
					if id, err := uuid.Parse(s); err == nil {
						out = append(out, id)
					}
				}
				return out
			}
			if err := polSvc.UpdateAttachments(req.Context(), u.ID, id,
				parseIDs("bundle_ids"), parseIDs("destination_ids")); err != nil {
				logger.Warn("update attachments", "err", err)
			}
			http.Redirect(w, req, "/ui/policies/"+id.String(), http.StatusSeeOther)
		})

		if cfg.DevMode {
			r.Post("/ui/policies/{id}/force-trigger", func(w http.ResponseWriter, req *http.Request) {
				u := userFrom(req.Context())
				id, err := uuid.Parse(chi.URLParam(req, "id"))
				if err != nil {
					http.Error(w, "bad id", http.StatusBadRequest)
					return
				}
				if err := polSvc.ForceTriggerDev(req.Context(), u.ID, id); err != nil {
					logger.Warn("force trigger", "err", err)
				}
				http.Redirect(w, req, "/ui/policies/"+id.String(), http.StatusSeeOther)
			})
		}

		r.Post("/ui/policies/{id}/{action}", func(w http.ResponseWriter, req *http.Request) {
			u := userFrom(req.Context())
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			actFn := map[string]func() error{
				"arm":     func() error { return polSvc.Arm(req.Context(), u.ID, id) },
				"suspend": func() error { return polSvc.Suspend(req.Context(), u.ID, id) },
				"resume":  func() error { return polSvc.Resume(req.Context(), u.ID, id) },
				"revoke":  func() error { return polSvc.Revoke(req.Context(), u.ID, id) },
			}
			fn, ok := actFn[chi.URLParam(req, "action")]
			if !ok {
				http.Error(w, "unknown action", http.StatusBadRequest)
				return
			}
			if err := fn(); err != nil {
				logger.Warn("policy action", "err", err)
			}
			http.Redirect(w, req, "/ui/policies/"+id.String(), http.StatusSeeOther)
		})
	})

	return nil
}

// summarizeConfig renders a short display string for a destination config.
// Never includes secret tokens; those are stored encrypted separately.
func summarizeConfig(kind string, cfg []byte) string {
	if len(cfg) == 0 {
		return ""
	}
	switch kind {
	case "webhook":
		var m map[string]any
		_ = json.Unmarshal(cfg, &m)
		if u, ok := m["url"].(string); ok {
			return u
		}
	case "email":
		var m struct {
			Recipients []string `json:"recipients"`
		}
		_ = json.Unmarshal(cfg, &m)
		return strings.Join(m.Recipients, ", ")
	}
	return ""
}

func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// fillSetup computes the guided first-run stepper. Hidden (ShowSetup=false)
// once the user has at least one armed policy — their runway is over,
// they know what they're doing.
func fillSetup(pd *PageData, bundles []store.ContentBundle, dests []store.Destination, policies []store.Policy) {
	// If any policy is armed/warning/grace/hold/triggered/releasing/released,
	// the user has completed the initial flow — retire the guide.
	for _, p := range policies {
		switch p.State {
		case "armed", "healthy", "warning", "grace", "hold",
			"triggered", "releasing", "released", "failed_partial":
			return
		}
	}

	steps := []SetupStep{
		{Num: 1, Title: "Upload a bundle", CTA: "/ui/bundles/new", CTAText: "Upload bundle",
			Blurb: "The encrypted material that will be released if you miss a check-in. Encrypted in your browser first."},
		{Num: 2, Title: "Add a destination", CTA: "/ui/destinations", CTAText: "Add destination",
			Blurb: "Where the bundle goes: a public landing page, an email recipient, or a webhook you control."},
		{Num: 3, Title: "Create a policy", CTA: "/ui/policies/new", CTAText: "Create policy",
			Blurb: "Check-in schedule, grace period, which bundle releases to which destination."},
		{Num: 4, Title: "Arm the policy", CTA: "/ui/dashboard", CTAText: "Arm from the policy page",
			Blurb: "Starts a 24-hour activation cooldown; you can cancel during that window. Then the timer runs."},
	}

	hasBundle := len(bundles) > 0
	hasDest := false
	for _, d := range dests {
		if d.RevokedAt == nil {
			hasDest = true
			break
		}
	}
	hasDraft := false
	for _, p := range policies {
		if p.State == "draft" {
			hasDraft = true
			break
		}
	}

	done := 0
	if hasBundle {
		steps[0].Status = "done"
		if len(bundles) == 1 {
			steps[0].Subtext = "1 bundle"
		} else {
			steps[0].Subtext = fmt.Sprintf("%d bundles", len(bundles))
		}
		done++
	}
	if hasDest {
		steps[1].Status = "done"
		done++
	}
	if hasDraft {
		steps[2].Status = "done"
		steps[2].Subtext = "draft created — open it to arm"
		done++
	}

	// Mark the first non-done step active; the rest pending.
	activeSet := false
	for i := range steps {
		if steps[i].Status == "done" {
			continue
		}
		if !activeSet {
			steps[i].Status = "active"
			activeSet = true
		} else {
			steps[i].Status = "pending"
		}
	}

	pd.ShowSetup = true
	pd.SetupProgress = done
	pd.SetupSteps = steps
}

// stateRank orders policy states by proximity to release. Higher = more urgent.
var stateRank = map[string]int{
	"healthy":   1,
	"warning":   2,
	"hold":      3,
	"grace":     4,
	"triggered": 5,
}

// fillCountdown populates the dashboard countdown fields based on the user's
// policies + their runtime states. The soonest-due armed policy drives the
// widget. If no armed policies exist, AnyArmed remains false.
func fillCountdown(pd *PageData, policies []store.Policy) {
	var soonest *time.Time
	worstRank := 0
	worstState := ""
	for _, p := range policies {
		if _, ok := stateRank[p.State]; !ok {
			continue
		}
		pd.AnyArmed = true
		if stateRank[p.State] > worstRank {
			worstRank = stateRank[p.State]
			worstState = p.State
		}
		// We don't have runtime here; caller passed policies only. Skip
		// per-policy due time — the PolicyRow in rows has NextDueAt. But the
		// dashboard handler builds rows from policies + runtime; reuse that.
	}
	pd.WorstState = worstState
	_ = soonest
}

// widget overwrites this each second with a live value; the server text is
// just the no-JS fallback.
// renderAuditRow formats an audit.Record for the user-facing log.
// Strips internal detail that isn't useful for a user, pretty-prints the
// payload for the expandable "details" disclosure.
func renderAuditRow(e audit.Record) AuditRow {
	row := AuditRow{
		Seq:            e.Seq,
		EventID:        e.ID.String(),
		EventType:      e.EventType,
		WhenHuman:      e.OccurredAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		PrevHashHex:    hex.EncodeToString(e.PrevHash[:]),
		PayloadHashHex: hex.EncodeToString(e.PayloadHash[:]),
	}
	switch e.ActorKind {
	case audit.ActorUser:
		row.ActorSummary = "you"
	case audit.ActorService:
		row.ActorSummary = "service (scheduler/release)"
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
		// Pretty-print JSON for the details drawer. Safe: payload is our
		// own serialization; html/template escapes it anyway.
		var v any
		if err := json.Unmarshal(e.Payload, &v); err == nil {
			if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
				row.PayloadPretty = string(pretty)
			}
		}
	}
	return row
}

// formatDelta returns the initial server-rendered countdown text. The JS
func formatDelta(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	days := int64(d / (24 * time.Hour))
	h := int64(d/time.Hour) % 24
	m := int64(d/time.Minute) % 60
	prefix := ""
	if neg {
		prefix = "Overdue by "
	}
	switch {
	case days > 0:
		return fmt.Sprintf("%s%dd %02dh %02dm", prefix, days, h, m)
	case h > 0:
		return fmt.Sprintf("%s%dh %02dm", prefix, h, m)
	default:
		return fmt.Sprintf("%s%dm", prefix, m)
	}
}

func humanBytes(n int64) string {
	const k = 1024
	if n < k {
		return itoa64(n) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / k
	i := 0
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	// One decimal if < 10, else rounded.
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, units[i])
	}
	return fmt.Sprintf("%.0f %s", v, units[i])
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 100000 {
			return def
		}
	}
	return n
}
