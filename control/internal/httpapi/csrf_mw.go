package httpapi

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gcottrell/deadman/control/internal/auth"
)

// csrfMiddleware enforces synchronizer-token CSRF protection on /ui/* POSTs.
//
// Design:
//
//   - GET / HEAD / OPTIONS pass through unchecked.
//   - Only paths starting with /ui/ are checked. /api/v1/* uses different
//     auth shapes (WebAuthn ceremonies have replay protection on the
//     challenge; future API tokens will carry their own auth header).
//   - Each authenticated session has a 32-byte csrf_token randomly
//     generated at session creation. Forms render it as base64url in a
//     hidden `csrf_token` field; AJAX clients pass it in `X-CSRF-Token`.
//   - On POST, the middleware reads the cookie, looks up the session,
//     and constant-time compares the form value to the stored token.
//   - If the request has no session cookie, the request continues
//     unchecked (handlers will reject it themselves with 401/redirect).
//     This keeps the login/register POST surface working — those POSTs
//     run pre-session.
//
// Mismatch => 403, no body, no leak of which side was wrong.
//
// This middleware also caps the request body for every /ui/ mutating request
// (maxUIFormBytes) before anything parses it. All /ui/ POSTs are small HTML
// forms; without the cap, the pre-session register/login endpoints would
// accept unbounded bodies into ParseForm — a memory-exhaustion vector.
// /api/v1/* is untouched (bundle upload has its own MaxBytesReader).
func csrfMiddleware(authSvc *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !needsCSRFCheck(r) {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxUIFormBytes)
			_, sess, err := authSvc.Authenticate(r.Context(), r)
			if err != nil || sess == nil {
				next.ServeHTTP(w, r)
				return
			}
			submitted := r.Header.Get("X-CSRF-Token")
			if submitted == "" {
				if err := r.ParseForm(); err == nil {
					submitted = r.FormValue("csrf_token")
				}
			}
			expected := base64.RawURLEncoding.EncodeToString(sess.CSRFToken)
			if submitted == "" || subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) != 1 {
				http.Error(w, "csrf token mismatch", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// maxUIFormBytes bounds /ui/ form POST bodies. 1 MiB is orders of magnitude
// above any legitimate form here (text fields only, no uploads).
const maxUIFormBytes = 1 << 20

func needsCSRFCheck(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/ui/")
}
