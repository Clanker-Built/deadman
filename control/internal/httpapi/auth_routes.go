package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/ratelimit"
)

// mountAuthRoutes attaches passkey registration/login endpoints under /api/v1/auth.
func mountAuthRoutes(r chi.Router, logger *slog.Logger, svc *auth.Service) {
	// Generous per-IP limits because Tor exits share IPs. Strict per-email
	// limits catch targeted brute-forcing against a specific account.
	ipRegister := ratelimit.New(0.5, 10, 10*time.Minute) // ~1 per 2s, burst 10
	ipLogin := ratelimit.New(2, 30, 10*time.Minute)      // 2 rps, burst 30
	emailLogin := ratelimit.New(0.1, 5, 30*time.Minute)  // ~6/hr, burst 5 per email

	ipKey := func(r *http.Request) string { return "ip:" + ratelimit.ClientIP(r) }
	emailKey := func(r *http.Request) string {
		// For /finish we get email via query; /begin via JSON body. Use
		// whichever is available. Peeking at the body would consume it,
		// so we only rate-limit on the query where present.
		if e := r.URL.Query().Get("email"); e != "" {
			return "email:" + e
		}
		return ""
	}

	limitRegisterBegin := ratelimit.Middleware(ipRegister, ipKey)
	limitLoginIP := ratelimit.Middleware(ipLogin, ipKey)
	limitLoginEmail := ratelimit.Middleware(emailLogin, emailKey)

	r.Route("/auth", func(r chi.Router) {
		r.With(limitRegisterBegin).Post("/register/begin", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Email       string `json:"email"`
				DisplayName string `json:"display_name"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			if body.Email == "" {
				httpError(w, http.StatusBadRequest, "email required")
				return
			}
			opts, sessionID, err := svc.BeginRegister(req.Context(), body.Email, body.DisplayName)
			if err != nil {
				logger.Error("begin register", "err", err)
				httpError(w, http.StatusInternalServerError, "begin register failed")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"session_id": sessionID,
				"options":    opts,
			})
		})

		r.With(limitLoginEmail, limitLoginIP).Post("/register/finish", func(w http.ResponseWriter, req *http.Request) {
			email := req.URL.Query().Get("email")
			sessionID := req.URL.Query().Get("session_id")
			if email == "" || sessionID == "" {
				httpError(w, http.StatusBadRequest, "email and session_id required")
				return
			}
			if err := svc.FinishRegister(req.Context(), email, sessionID, req); err != nil {
				logger.Error("finish register", "err", err)
				httpError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
		})

		r.With(limitLoginIP).Post("/login/begin", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Email string `json:"email"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Email == "" {
				httpError(w, http.StatusBadRequest, "email required")
				return
			}
			opts, sessionID, err := svc.BeginLogin(req.Context(), body.Email)
			if err != nil {
				logger.Error("begin login", "err", err)
				httpError(w, http.StatusUnauthorized, "login unavailable")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"session_id": sessionID,
				"options":    opts,
			})
		})

		r.With(limitLoginEmail, limitLoginIP).Post("/login/finish", func(w http.ResponseWriter, req *http.Request) {
			email := req.URL.Query().Get("email")
			sessionID := req.URL.Query().Get("session_id")
			if email == "" || sessionID == "" {
				httpError(w, http.StatusBadRequest, "email and session_id required")
				return
			}
			uid, err := svc.FinishLogin(req.Context(), email, sessionID, req)
			if err != nil {
				logger.Error("finish login", "err", err)
				httpError(w, http.StatusUnauthorized, "login failed")
				return
			}
			token, _, err := svc.IssueSession(req.Context(), uid, nil)
			if err != nil {
				logger.Error("issue session", "err", err)
				httpError(w, http.StatusInternalServerError, "session issue failed")
				return
			}
			// Secure=false for dev; set via request's TLS state in prod.
			auth.SetSessionCookie(w, token, req.TLS != nil)
			writeJSON(w, http.StatusOK, map[string]string{"user_id": uid.String()})
		})
	})
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
