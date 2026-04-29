package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/store"
)

// SessionCookieName is the HTTP cookie that carries the opaque session token.
// The token is random bytes; only its SHA-256 hash lives in the DB so a DB
// read cannot impersonate users.
const SessionCookieName = "deadman_session"

// SessionTTL is the default session lifetime.
const SessionTTL = 24 * time.Hour

// IssueSession mints a session for userID and returns the opaque token. The
// caller should Set-Cookie it with Secure, HttpOnly, SameSite=Lax.
func (s *Service) IssueSession(ctx context.Context, userID uuid.UUID, deviceID *uuid.UUID) (string, *store.Session, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return "", nil, err
	}
	hash := sha256.Sum256(tok)
	var sess *store.Session
	err := s.store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		var e error
		sess, e = store.CreateSession(ctx, q, userID, deviceID, hash[:], SessionTTL)
		return e
	})
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(tok), sess, nil
}

// SetSessionCookie writes the cookie with hardened flags.
func SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

// ErrUnauthorized is returned by Authenticate when no valid session is found.
var ErrUnauthorized = errors.New("auth: unauthorized")

// Authenticate resolves a request to a user ID via the session cookie.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (uuid.UUID, *store.Session, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return uuid.Nil, nil, ErrUnauthorized
	}
	tok, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return uuid.Nil, nil, ErrUnauthorized
	}
	hash := sha256.Sum256(tok)
	sess, err := store.GetSessionByTokenHash(ctx, s.store.Pool, hash[:])
	if err != nil {
		return uuid.Nil, nil, ErrUnauthorized
	}
	if sess.RevokedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		return uuid.Nil, nil, ErrUnauthorized
	}
	return sess.UserID, sess, nil
}

type ctxKey int

const (
	ctxKeyUserID ctxKey = iota
	ctxKeySession
)

// RequireSession is middleware for protected routes.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, sess, err := s.Authenticate(r.Context(), r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUserID, uid)
		ctx = context.WithValue(ctx, ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext extracts the authenticated user ID.
func UserFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(ctxKeyUserID).(uuid.UUID)
	return v, ok
}

// SessionFromContext extracts the active session.
func SessionFromContext(ctx context.Context) (*store.Session, bool) {
	v, ok := ctx.Value(ctxKeySession).(*store.Session)
	return v, ok
}
