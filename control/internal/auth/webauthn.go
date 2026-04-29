// Package auth handles identity: WebAuthn/passkey registration and login.
//
// We use the go-webauthn library (github.com/go-webauthn/webauthn). The
// library gives us RP config + ceremony state; we wire it to our user and
// credential tables, and to the audit ledger so every register/login lands
// in the tamper-evident log.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/store"
)

// Config is the relying-party configuration.
type Config struct {
	RPDisplayName string   // e.g. "Deadman"
	RPID          string   // e.g. "localhost" or "deadman.example"
	RPOrigins     []string // e.g. ["http://localhost:8080"]
	// BootstrapAdminEmail: first user to log in with this email (case-
	// insensitive) auto-promotes to admin, but only if no admin exists yet.
	// Emits audit "admin.promoted" with reason=bootstrap.
	BootstrapAdminEmail string
}

// Service is the passkey ceremony coordinator.
type Service struct {
	w                   *webauthn.WebAuthn
	store               *store.Store
	ledger              *audit.Ledger
	bootstrapAdminEmail string
	// In-memory ceremony state keyed by session ID. Production should use
	// Redis or a signed cookie; fine for M1 dev.
	pending  map[string]*webauthn.SessionData
	pendingM sync.Mutex
}

func NewService(cfg Config, s *store.Store, l *audit.Ledger) (*Service, error) {
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}
	return &Service{
		w:                   w,
		store:               s,
		ledger:              l,
		bootstrapAdminEmail: cfg.BootstrapAdminEmail,
		pending:             make(map[string]*webauthn.SessionData),
	}, nil
}

// Store exposes the underlying store for handlers that need direct DB access
// (admin panel, step-up bookkeeping).
func (s *Service) Store() *store.Store { return s.store }

// Ledger exposes the ledger for admin-action audit writes.
func (s *Service) Ledger() *audit.Ledger { return s.ledger }

// userAdapter implements webauthn.User against our store.User.
type userAdapter struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *userAdapter) WebAuthnID() []byte                         { b, _ := u.id.MarshalBinary(); return b }
func (u *userAdapter) WebAuthnName() string                       { return u.name }
func (u *userAdapter) WebAuthnDisplayName() string                { return u.displayName }
func (u *userAdapter) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) loadUser(ctx context.Context, u *store.User) (*userAdapter, error) {
	creds, err := store.ListUserCredentials(ctx, s.store.Pool, u.ID)
	if err != nil {
		return nil, err
	}
	wc := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wc = append(wc, webauthn.Credential{
			ID:        c.ID,
			PublicKey: c.PublicKey,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}
	return &userAdapter{id: u.ID, name: u.Email, displayName: u.DisplayName, creds: wc}, nil
}

// BeginRegister starts passkey registration. If the email doesn't exist it
// creates a draft user. Returns the credential creation options the client
// will pass to navigator.credentials.create(), plus a sessionID the caller
// must echo to FinishRegister.
func (s *Service) BeginRegister(ctx context.Context, email, displayName string) (opts *protocol.CredentialCreation, sessionID string, err error) {
	var u *store.User
	u, err = store.GetUserByEmail(ctx, s.store.Pool, email)
	if errors.Is(err, store.ErrNotFound) {
		err = s.store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
			var e error
			u, e = store.CreateUser(ctx, q, email, displayName, nil)
			if e != nil {
				return e
			}
			_, e = s.ledger.AppendTx(ctx, q, audit.Event{
				ActorKind: audit.ActorUser,
				ActorID:   &u.ID,
				EventType: "user.created",
				Payload:   map[string]any{"email": email},
			})
			return e
		})
	}
	if err != nil {
		return nil, "", err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	opts, sess, err := s.w.BeginRegistration(wu)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}
	sessionID = uuid.NewString()
	s.pendingM.Lock()
	s.pending[sessionID] = sess
	s.pendingM.Unlock()
	return opts, sessionID, nil
}

// FinishRegister completes the ceremony and persists the new credential.
func (s *Service) FinishRegister(ctx context.Context, email, sessionID string, response *http.Request) error {
	s.pendingM.Lock()
	sess, ok := s.pending[sessionID]
	if ok {
		delete(s.pending, sessionID)
	}
	s.pendingM.Unlock()
	if !ok {
		return errors.New("auth: unknown session")
	}
	u, err := store.GetUserByEmail(ctx, s.store.Pool, email)
	if err != nil {
		return err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return err
	}
	cred, err := s.w.FinishRegistration(wu, *sess, response)
	if err != nil {
		return fmt.Errorf("finish registration: %w", err)
	}
	err = s.store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		if err := store.InsertWebAuthnCredential(ctx, q, &store.WebAuthnCredential{
			ID:             cred.ID,
			UserID:         u.ID,
			PublicKey:      cred.PublicKey,
			SignCount:      cred.Authenticator.SignCount,
			Transports:     transportsStrings(cred.Transport),
			AAGUID:         cred.Authenticator.AAGUID,
			Label:          "passkey",
			BackupEligible: cred.Flags.BackupEligible,
			BackupState:    cred.Flags.BackupState,
		}); err != nil {
			return err
		}
		_, err := s.ledger.AppendTx(ctx, q, audit.Event{
			ActorKind:   audit.ActorUser,
			ActorID:     &u.ID,
			EventType:   "passkey.registered",
			SubjectKind: "user",
			SubjectID:   &u.ID,
			Payload: map[string]any{
				"credential_id": fmt.Sprintf("%x", cred.ID),
				"aaguid":        fmt.Sprintf("%x", cred.Authenticator.AAGUID),
			},
		})
		return err
	})
	return err
}

// BeginLogin starts a passkey assertion ceremony.
func (s *Service) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, string, error) {
	u, err := store.GetUserByEmail(ctx, s.store.Pool, email)
	if err != nil {
		return nil, "", err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	opts, sess, err := s.w.BeginLogin(wu)
	if err != nil {
		return nil, "", fmt.Errorf("begin login: %w", err)
	}
	sessionID := uuid.NewString()
	s.pendingM.Lock()
	s.pending[sessionID] = sess
	s.pendingM.Unlock()
	return opts, sessionID, nil
}

// FinishLogin completes assertion and returns the authenticated user ID.
func (s *Service) FinishLogin(ctx context.Context, email, sessionID string, response *http.Request) (uuid.UUID, error) {
	s.pendingM.Lock()
	sess, ok := s.pending[sessionID]
	if ok {
		delete(s.pending, sessionID)
	}
	s.pendingM.Unlock()
	if !ok {
		return uuid.Nil, errors.New("auth: unknown session")
	}
	u, err := store.GetUserByEmail(ctx, s.store.Pool, email)
	if err != nil {
		return uuid.Nil, err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return uuid.Nil, err
	}
	cred, err := s.w.FinishLogin(wu, *sess, response)
	if err != nil {
		return uuid.Nil, fmt.Errorf("finish login: %w", err)
	}
	err = s.store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		if err := store.UpdateCredentialSignCount(ctx, q, cred.ID, cred.Authenticator.SignCount); err != nil {
			return err
		}
		// BackupState can legitimately change as the authenticator syncs.
		if err := store.UpdateCredentialFlags(ctx, q, cred.ID, cred.Flags.BackupState); err != nil {
			return err
		}
		if _, err := s.ledger.AppendTx(ctx, q, audit.Event{
			ActorKind:   audit.ActorUser,
			ActorID:     &u.ID,
			EventType:   "user.login",
			SubjectKind: "user",
			SubjectID:   &u.ID,
			Payload:     map[string]any{"credential_id": fmt.Sprintf("%x", cred.ID)},
		}); err != nil {
			return err
		}
		// Bootstrap admin promotion: first login matching the configured
		// email, only while zero admins exist. Idempotent after that.
		if s.bootstrapAdminEmail != "" && !u.IsAdmin &&
			strings.EqualFold(u.Email, s.bootstrapAdminEmail) {
			n, err := store.CountAdmins(ctx, q)
			if err != nil {
				return err
			}
			if n == 0 {
				if err := store.SetUserAdmin(ctx, q, u.ID, true); err != nil {
					return err
				}
				if _, err := s.ledger.AppendTx(ctx, q, audit.Event{
					ActorKind:   audit.ActorSystem,
					EventType:   "admin.promoted",
					SubjectKind: "user",
					SubjectID:   &u.ID,
					Payload:     map[string]any{"reason": "bootstrap", "email": u.Email},
				}); err != nil {
					return err
				}
				// Loud, repeated warning so the operator knows to remove
				// DEADMAN_BOOTSTRAP_ADMIN_EMAIL from the env file. The
				// guard on `n == 0` already prevents re-promotion, but
				// leaving the env var set means the value is sitting in
				// /etc/deadman/deadman.env unnecessarily.
				slog.Warn("BOOTSTRAP ADMIN promotion fired — clear DEADMAN_BOOTSTRAP_ADMIN_EMAIL from /etc/deadman/deadman.env and restart the service",
					"user_id", u.ID, "email", u.Email)
			}
		}
		return nil
	})
	return u.ID, err
}


// WriteJSON helper for ceremony responses.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func transportsStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}
