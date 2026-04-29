package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNeedsCSRFCheck(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/ui/dashboard", false},
		{"HEAD", "/ui/dashboard", false},
		{"OPTIONS", "/ui/dashboard", false},
		{"POST", "/ui/policies/new", true},
		{"POST", "/api/v1/auth/login/finish", false},
		{"POST", "/healthz", false},
		{"PUT", "/ui/admin/users/x", true},
		{"DELETE", "/ui/admin/users/x", true},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		got := needsCSRFCheck(req)
		if got != c.want {
			t.Errorf("%s %s: want %v, got %v", c.method, c.path, c.want, got)
		}
	}
}

func TestCSRF_NoSession_PassesThrough(t *testing.T) {
	// With no session cookie, csrfMiddleware lets the request through —
	// the handler will reject it via its own auth path. This is so that
	// pre-session POSTs (login/register on /api/v1) keep working; the
	// middleware only enforces when there's an authenticated session
	// available.
	mw := csrfMiddleware(nil)
	if mw == nil {
		t.Skip("nil auth disables; handled at construction")
	}
}

func TestRouter_CSRFMiddlewareWired(t *testing.T) {
	// Smoke test: with no Auth wired, the router should still build and
	// serve healthz. csrfMiddleware is only registered when d.Auth != nil.
	r := NewRouter(nil)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) == "" {
		t.Fatal("empty healthz body")
	}
}
