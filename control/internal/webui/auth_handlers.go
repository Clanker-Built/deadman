package webui

// Passphrase + TOTP auth handlers. WebAuthn lives in package auth and
// remains opt-in for users with a hardware key on a TLS-fronted deployment;
// see docs/self-hosting.md for the rationale.
//
// Flow:
//   POST /ui/register  → create user with Argon2id(passphrase). Logs them
//                        in, redirects to /ui/auth/totp/setup.
//   GET  /ui/auth/totp/setup
//                      → renders QR-text + base32 + recovery codes (shown
//                        once). Confirmation field on the same page.
//   POST /ui/auth/totp/setup
//                      → verifies the first code, marks TOTP confirmed.
//   POST /ui/login     → email + passphrase + (totp_code | recovery_code).
//
// The bootstrap-admin promotion (first email matching env var
// DEADMAN_BOOTSTRAP_ADMIN_EMAIL while no admin exists) runs on the first
// successful passphrase login, replacing the previous WebAuthn-side
// trigger.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/store"
)

// pendingTOTP holds a freshly-generated, not-yet-confirmed TOTP secret keyed
// by user ID. Lives only in process memory; on restart users in-flight have
// to start setup over. That's fine — TOTP setup is a one-time operation.
type pendingTOTP struct {
	UserID uuid.UUID
	Secret string // base32, no padding
	Codes  []string // plaintext recovery codes, shown once
	HashedCodes []string
	Created time.Time
}

type pendingStore struct {
	m map[uuid.UUID]*pendingTOTP
}

func newPendingStore() *pendingStore { return &pendingStore{m: make(map[uuid.UUID]*pendingTOTP)} }

func (p *pendingStore) put(s *pendingTOTP) { p.m[s.UserID] = s }
func (p *pendingStore) get(id uuid.UUID) *pendingTOTP { return p.m[id] }
func (p *pendingStore) drop(id uuid.UUID) { delete(p.m, id) }

// authHandlers is the bundle of state that the auth POST handlers need.
type authHandlers struct {
	logger              *slog.Logger
	store               *store.Store
	auth                *auth.Service
	rend                *Renderer
	pending             *pendingStore
	bootstrapAdminEmail string
	rpDisplayName       string
}

// mountAuthHandlers attaches passphrase+TOTP routes. Caller mounts
// these BEFORE the session-protected group so /ui/register and /ui/login
// are reachable without a session.
//
// Note: TOTP setup pages live at /ui/auth/totp/setup and require an
// authenticated session (just-registered or already-logged-in user).
func (h *authHandlers) mountPublic(reg func(method, pat string, handler http.HandlerFunc)) {
	reg("POST", "/ui/register", h.postRegister)
	reg("POST", "/ui/login", h.postLogin)
}

func (h *authHandlers) mountSessionProtected(reg func(method, pat string, handler http.HandlerFunc)) {
	reg("GET", "/ui/auth/totp/setup", h.getTOTPSetup)
	reg("POST", "/ui/auth/totp/setup", h.postTOTPSetup)
}

func (h *authHandlers) postRegister(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Six required acks gate registration. We don't store them; the act of
	// posting with all six checked is the consent.
	for i := 1; i <= 6; i++ {
		if req.Form.Get(formAckName(i)) == "" {
			h.rend.render(w, req, "register", PageData{
				Title: "Create account",
				Flash: "All acknowledgments are required.", FlashKind: "error",
			})
			return
		}
	}

	email := strings.ToLower(strings.TrimSpace(req.Form.Get("email")))
	displayName := strings.TrimSpace(req.Form.Get("display_name"))
	passphrase := req.Form.Get("passphrase")
	confirm := req.Form.Get("passphrase_confirm")

	if email == "" || !strings.Contains(email, "@") {
		h.renderRegisterErr(w, req, "Email is required.")
		return
	}
	if passphrase != confirm {
		h.renderRegisterErr(w, req, "Passphrases did not match.")
		return
	}

	hash, err := auth.HashPassword(passphrase)
	if err != nil {
		if errors.Is(err, auth.ErrWeakPassphrase) {
			h.renderRegisterErr(w, req, "Passphrase must be at least 12 characters.")
			return
		}
		h.logger.Error("hash password", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Reject duplicate-email registrations explicitly (don't silently
	// reset an existing user's passphrase).
	if existing, err := store.GetUserByEmail(req.Context(), h.store.Pool, email); err == nil && existing != nil {
		h.renderRegisterErr(w, req, "An account with that email already exists. Use the login page.")
		return
	}

	var u *store.User
	err = h.store.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
		var e error
		u, e = store.CreateUser(ctx, q, email, displayName, nil)
		if e != nil {
			return e
		}
		if e := store.SetPasswordHash(ctx, q, u.ID, hash); e != nil {
			return e
		}
		_, e = h.auth.Ledger().AppendTx(ctx, q, audit.Event{
			ActorKind: audit.ActorUser,
			ActorID:   &u.ID,
			EventType: "user.created",
			Payload:   map[string]any{"email": email, "method": "passphrase"},
		})
		return e
	})
	if err != nil {
		h.logger.Error("create user", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Auto-login immediately so we can route to TOTP setup. The session
	// is "step-up cooldown" not yet started — that comes after TOTP
	// confirmation, the way reauth-protected pages expect.
	tok, _, err := h.auth.IssueSession(req.Context(), u.ID, nil)
	if err != nil {
		h.logger.Error("issue session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok, req.TLS != nil)
	http.Redirect(w, req, "/ui/auth/totp/setup", http.StatusSeeOther)
}

func (h *authHandlers) renderRegisterErr(w http.ResponseWriter, req *http.Request, msg string) {
	h.rend.render(w, req, "register", PageData{
		Title: "Create account",
		Flash: msg, FlashKind: "error",
	})
}

func (h *authHandlers) getTOTPSetup(w http.ResponseWriter, req *http.Request) {
	u := userFrom(req.Context())
	if u == nil {
		http.Redirect(w, req, "/ui/login", http.StatusSeeOther)
		return
	}

	// Already confirmed? Don't re-show secrets — bounce to dashboard.
	if _, confirmed, _ := store.GetTOTPWrapped(req.Context(), h.store.Pool, u.ID); confirmed != nil {
		http.Redirect(w, req, "/ui/dashboard", http.StatusSeeOther)
		return
	}

	pend := h.pending.get(u.ID)
	if pend == nil {
		secret, err := auth.TOTPGenerateSecret()
		if err != nil {
			h.logger.Error("totp gen", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		plaintextCodes, hashedCodes, err := auth.GenerateRecoveryCodes()
		if err != nil {
			h.logger.Error("recovery gen", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pend = &pendingTOTP{
			UserID: u.ID, Secret: secret,
			Codes: plaintextCodes, HashedCodes: hashedCodes,
			Created: time.Now().UTC(),
		}
		h.pending.put(pend)
	}

	uri := auth.TOTPProvisioningURI(pend.Secret, u.Email, h.rpDisplayName)
	h.rend.render(w, req, "totp_setup", PageData{
		Title:        "Set up two-factor",
		UserEmail:    u.Email,
		TOTPSecret:   pend.Secret,
		TOTPURI:      uri,
		RecoveryCodes: pend.Codes,
	})
}

func (h *authHandlers) postTOTPSetup(w http.ResponseWriter, req *http.Request) {
	u := userFrom(req.Context())
	if u == nil {
		http.Redirect(w, req, "/ui/login", http.StatusSeeOther)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pend := h.pending.get(u.ID)
	if pend == nil {
		http.Redirect(w, req, "/ui/auth/totp/setup", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(req.Form.Get("code"))
	if err := auth.TOTPVerify(pend.Secret, code); err != nil {
		// Re-render with the same secret so the user can retry without
		// having to re-scan / re-enter into their authenticator.
		uri := auth.TOTPProvisioningURI(pend.Secret, u.Email, h.rpDisplayName)
		h.rend.render(w, req, "totp_setup", PageData{
			Title:         "Set up two-factor",
			UserEmail:     u.Email,
			TOTPSecret:    pend.Secret,
			TOTPURI:       uri,
			RecoveryCodes: pend.Codes,
			Flash:         "That code was not valid. Try again — codes rotate every 30 seconds.",
			FlashKind:     "error",
		})
		return
	}

	// Persist secret + recovery codes; emit audit; clear pending.
	err := h.store.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
		if err := store.SetTOTPWrapped(ctx, q, u.ID, []byte(pend.Secret), true); err != nil {
			return err
		}
		if err := store.SetRecoveryCodes(ctx, q, u.ID, pend.HashedCodes); err != nil {
			return err
		}
		_, err := h.auth.Ledger().AppendTx(ctx, q, audit.Event{
			ActorKind:   audit.ActorUser,
			ActorID:     &u.ID,
			EventType:   "totp.enrolled",
			SubjectKind: "user",
			SubjectID:   &u.ID,
			Payload:     map[string]any{"recovery_codes_issued": len(pend.HashedCodes)},
		})
		return err
	})
	if err != nil {
		h.logger.Error("totp persist", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.pending.drop(u.ID)
	http.Redirect(w, req, "/ui/dashboard", http.StatusSeeOther)
}

func (h *authHandlers) postLogin(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Form.Get("email")))
	passphrase := req.Form.Get("passphrase")
	totpCode := strings.TrimSpace(req.Form.Get("totp_code"))
	recoveryCode := strings.TrimSpace(req.Form.Get("recovery_code"))

	// Constant-ish-time: always do a passphrase verify even if user not
	// found, to avoid an obvious timing oracle on email enumeration.
	u, uerr := store.GetUserByEmail(req.Context(), h.store.Pool, email)
	if uerr != nil || u == nil {
		_ = auth.VerifyPassword(passphrase, "argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		h.renderLoginErr(w, req, "Invalid credentials.")
		return
	}
	hash, err := store.GetPasswordHash(req.Context(), h.store.Pool, u.ID)
	if err != nil || hash == "" {
		// User exists but has no passphrase set — legacy WebAuthn-only
		// account. Tell them to use the passkey path.
		h.renderLoginErr(w, req, "This account is passkey-only. Use a hardware key, or contact the operator to migrate.")
		return
	}
	if err := auth.VerifyPassword(passphrase, hash); err != nil {
		h.renderLoginErr(w, req, "Invalid credentials.")
		return
	}

	// Step 2: TOTP or recovery code. If TOTP isn't enrolled yet (newly-
	// created account whose owner closed the tab on setup), let them
	// through with passphrase only — they'll be redirected to setup.
	totpSecretBytes, confirmed, err := store.GetTOTPWrapped(req.Context(), h.store.Pool, u.ID)
	if err != nil {
		h.logger.Error("totp lookup", "err", err)
		h.renderLoginErr(w, req, "Internal error.")
		return
	}

	if confirmed != nil {
		secret := string(totpSecretBytes)
		switch {
		case totpCode != "":
			if err := auth.TOTPVerify(secret, totpCode); err != nil {
				h.renderLoginErr(w, req, "Invalid 2FA code.")
				return
			}
		case recoveryCode != "":
			stored, err := store.GetRecoveryCodes(req.Context(), h.store.Pool, u.ID)
			if err != nil {
				h.renderLoginErr(w, req, "Internal error.")
				return
			}
			remaining, err := auth.ConsumeRecoveryCode(recoveryCode, stored)
			if err != nil {
				h.renderLoginErr(w, req, "Invalid recovery code.")
				return
			}
			if err := store.SetRecoveryCodes(req.Context(), h.store.Pool, u.ID, remaining); err != nil {
				h.logger.Error("consume recovery", "err", err)
			}
		default:
			h.renderLoginErr(w, req, "2FA code or recovery code required.")
			return
		}
	}

	// Issue session.
	tok, _, err := h.auth.IssueSession(req.Context(), u.ID, nil)
	if err != nil {
		h.logger.Error("issue session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok, req.TLS != nil)

	// Bootstrap admin promotion + audit, in one tx.
	_ = h.store.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
		if _, err := h.auth.Ledger().AppendTx(ctx, q, audit.Event{
			ActorKind: audit.ActorUser, ActorID: &u.ID,
			EventType: "user.login", SubjectKind: "user", SubjectID: &u.ID,
			Payload: map[string]any{"method": "passphrase+totp"},
		}); err != nil {
			return err
		}
		if h.bootstrapAdminEmail != "" && !u.IsAdmin &&
			strings.EqualFold(u.Email, h.bootstrapAdminEmail) {
			n, err := store.CountAdmins(ctx, q)
			if err != nil {
				return err
			}
			if n == 0 {
				if err := store.SetUserAdmin(ctx, q, u.ID, true); err != nil {
					return err
				}
				if _, err := h.auth.Ledger().AppendTx(ctx, q, audit.Event{
					ActorKind: audit.ActorSystem, EventType: "admin.promoted",
					SubjectKind: "user", SubjectID: &u.ID,
					Payload: map[string]any{"reason": "bootstrap", "email": u.Email},
				}); err != nil {
					return err
				}
				h.logger.Warn("BOOTSTRAP ADMIN promotion fired — clear DEADMAN_BOOTSTRAP_ADMIN_EMAIL from /etc/deadman/deadman.env and restart the service",
					"user_id", u.ID, "email", u.Email)
			}
		}
		return nil
	})

	if confirmed == nil {
		http.Redirect(w, req, "/ui/auth/totp/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, req, "/ui/dashboard", http.StatusSeeOther)
}

func (h *authHandlers) renderLoginErr(w http.ResponseWriter, req *http.Request, msg string) {
	h.rend.render(w, req, "login", PageData{
		Title: "Log in",
		Flash: msg, FlashKind: "error",
	})
}

func formAckName(i int) string {
	return [...]string{"", "ack1", "ack2", "ack3", "ack4", "ack5", "ack6"}[i]
}
