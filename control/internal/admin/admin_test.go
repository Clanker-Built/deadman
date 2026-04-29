package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/store"
)

// requireDB skips the test if no test DB is configured; mirrors the pattern
// used by the store and audit packages.
func requireDB(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DEADMAN_DATABASE_URL")
	}
	if url == "" {
		t.Skip("no DEADMAN_TEST_DATABASE_URL / DEADMAN_DATABASE_URL set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func newTestDeps(t *testing.T, s *store.Store) (*Deps, *auth.Service) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.NewLedger(priv)
	authSvc, err := auth.NewService(auth.Config{
		RPDisplayName: "Test", RPID: "localhost",
		RPOrigins: []string{"http://localhost"},
	}, s, ledger)
	if err != nil {
		t.Fatal(err)
	}
	d := &Deps{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Store:  s, Auth: authSvc, Ledger: ledger,
	}
	return d, authSvc
}

// makeUserWithSession inserts a user (admin or not) and a session for them.
// stepUpAge controls how long ago the step-up assertion happened; pass 0
// for "just now". Returns the cookie value to send back on requests.
func makeUserWithSession(t *testing.T, s *store.Store, isAdmin bool, stepUpAge time.Duration) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	email := "admin-test-" + uuid.NewString() + "@test.local"
	var u *store.User
	err := s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		var e error
		u, e = store.CreateUser(ctx, q, email, "T", nil)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if isAdmin {
		if err := store.SetUserAdmin(ctx, s.Pool, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, u.ID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID)
	})

	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	hash := sha256.Sum256(tok)
	if _, err := store.CreateSession(ctx, s.Pool, u.ID, nil, hash[:], 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// step_up_at is set to now() inside CreateSession. Move it back if we're
	// simulating a stale step-up.
	if stepUpAge > 0 {
		when := time.Now().UTC().Add(-stepUpAge)
		if _, err := s.Pool.Exec(ctx,
			`UPDATE sessions SET step_up_at = $2 WHERE token_hash = $1`,
			hash[:], when); err != nil {
			t.Fatal(err)
		}
	}
	return u.ID, base64.RawURLEncoding.EncodeToString(tok)
}

func runMW(t *testing.T, d *Deps, cookie string, target string) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		u := AdminUserFromContext(r.Context())
		if u == nil {
			t.Fatalf("admin user not in ctx")
		}
		w.WriteHeader(http.StatusTeapot)
	})
	h := d.RequireAdmin(next)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	}
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusTeapot && !called {
		t.Fatalf("teapot status without next being called?")
	}
	return rec
}

func TestRequireAdmin_NoSession_RedirectsToLogin(t *testing.T) {
	s := requireDB(t)
	d, _ := newTestDeps(t, s)
	rec := runMW(t, d, "", "/ui/admin/")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/ui/login" {
		t.Fatalf("want /ui/login, got %q", got)
	}
}

func TestRequireAdmin_NonAdmin_404s(t *testing.T) {
	s := requireDB(t)
	d, _ := newTestDeps(t, s)
	_, cookie := makeUserWithSession(t, s, /*isAdmin=*/ false, 0)
	rec := runMW(t, d, cookie, "/ui/admin/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 (do not leak admin surface), got %d", rec.Code)
	}
}

func TestRequireAdmin_StaleStepUp_RedirectsToReauth(t *testing.T) {
	s := requireDB(t)
	d, _ := newTestDeps(t, s)
	_, cookie := makeUserWithSession(t, s, true, StepUpWindow+time.Minute)
	rec := runMW(t, d, cookie, "/ui/admin/users")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" || loc[:len("/ui/admin/reauth")] != "/ui/admin/reauth" {
		t.Fatalf("want /ui/admin/reauth, got %q", loc)
	}
}

func TestRequireAdmin_FreshAdmin_PassesThrough(t *testing.T) {
	s := requireDB(t)
	d, _ := newTestDeps(t, s)
	_, cookie := makeUserWithSession(t, s, true, 0)
	rec := runMW(t, d, cookie, "/ui/admin/")
	if rec.Code != http.StatusTeapot {
		t.Fatalf("want 418 (next handler), got %d", rec.Code)
	}
}

func TestAuditAdminAction_AppendsToLedger(t *testing.T) {
	s := requireDB(t)
	d, _ := newTestDeps(t, s)
	uid, _ := makeUserWithSession(t, s, true, 0)

	d.AuditAdminAction(context.Background(), uid, "admin.test_event", "user", &uid,
		map[string]any{"k": "v"})

	// The ledger.Append path is opaque from here; verify by reading the
	// most recent admin.test_event for this actor.
	var n int
	if err := s.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events
		 WHERE event_type = 'admin.test_event' AND actor_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 audit event, got %d", n)
	}
}
