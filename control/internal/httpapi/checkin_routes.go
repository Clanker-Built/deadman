package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/checkin"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/ratelimit"
	"github.com/gcottrell/deadman/control/internal/store"
)

type verifyReq struct {
	DeviceID  string `json:"device_id"`
	Nonce     string `json:"nonce"` // base64url
	Counter   int64  `json:"counter"`
	Signature string `json:"signature"` // base64url
}

func mountCheckinRoutes(r chi.Router, logger *slog.Logger, s *store.Store, authSvc *auth.Service, ledger *audit.Ledger, ns *checkin.Store, polSvc *policy.Service) {
	// Check-in endpoints: permissive enough for anxious users to mash the
	// button, strict enough to catch brute-force replay probes. 2/sec avg,
	// burst 20, per-user.
	perUserCheckin := ratelimit.New(2, 20, 10*time.Minute)
	userKey := func(r *http.Request) string {
		if uid, ok := auth.UserFromContext(r.Context()); ok {
			return "user:" + uid.String()
		}
		return ""
	}
	limitCheckin := ratelimit.Middleware(perUserCheckin, userKey)

	r.Route("/checkin", func(r chi.Router) {
		r.Use(authSvc.RequireSession)
		r.Use(limitCheckin)

		r.Post("/nonce", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			var body struct {
				DeviceID string `json:"device_id"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			did, err := uuid.Parse(body.DeviceID)
			if err != nil {
				httpError(w, http.StatusBadRequest, "device_id must be uuid")
				return
			}
			dev, err := store.GetDevice(req.Context(), s.Pool, did)
			if err != nil || dev.UserID != uid || dev.RevokedAt != nil {
				httpError(w, http.StatusForbidden, "device not available")
				return
			}
			is, err := ns.Issue(did, uid)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "nonce issue failed")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"nonce":      base64.RawURLEncoding.EncodeToString(is.Nonce[:]),
				"expires_at": is.ExpiresAt,
				"domain":     checkin.DomainPrefix,
			})
		})

		r.Post("/verify", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			var body verifyReq
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			did, err := uuid.Parse(body.DeviceID)
			if err != nil {
				httpError(w, http.StatusBadRequest, "device_id must be uuid")
				return
			}
			nonceB, err := base64.RawURLEncoding.DecodeString(body.Nonce)
			if err != nil || len(nonceB) != checkin.NonceSize {
				httpError(w, http.StatusBadRequest, "bad nonce")
				return
			}
			sig, err := base64.RawURLEncoding.DecodeString(body.Signature)
			if err != nil || len(sig) != ed25519.SignatureSize {
				httpError(w, http.StatusBadRequest, "bad signature")
				return
			}
			dev, err := store.GetDevice(req.Context(), s.Pool, did)
			if err != nil || dev.UserID != uid || dev.RevokedAt != nil {
				httpError(w, http.StatusForbidden, "device not available")
				return
			}
			var nonce [checkin.NonceSize]byte
			copy(nonce[:], nonceB)
			if _, err := checkin.Verify(req.Context(), ns, nonce, body.Counter, sig, dev.DevicePubKey, dev.MonotonicCounter); err != nil {
				logger.Warn("checkin verify failed", "device_id", did, "err", err)
				httpError(w, http.StatusUnauthorized, "check-in verification failed")
				return
			}

			txErr := s.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
				if _, err := store.UpdateDeviceCheckIn(ctx, q, did, body.Counter); err != nil {
					return err
				}
				_, err := ledger.AppendTx(ctx, q, audit.Event{
					ActorKind:   audit.ActorDevice,
					ActorID:     &did,
					EventType:   "checkin.verified",
					SubjectKind: "user",
					SubjectID:   &uid,
					Payload:     map[string]any{"counter": body.Counter},
				})
				return err
			})
			if txErr != nil {
				logger.Error("checkin commit", "err", txErr)
				httpError(w, http.StatusInternalServerError, "checkin commit failed")
				return
			}
			// Advance all armed policies owned by this user.
			advanced := 0
			if polSvc != nil {
				n, err := polSvc.CheckInAllArmed(req.Context(), uid, &did)
				if err != nil {
					logger.Warn("checkin advance policies", "err", err)
				}
				advanced = n
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":            "ok",
				"policies_advanced": advanced,
			})
		})
	})
}
