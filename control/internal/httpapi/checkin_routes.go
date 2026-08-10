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
			// Delayed-trust window (§29.2, TrustDelay): a freshly enrolled
			// device cannot verify check-ins until trusted_after has passed.
			if time.Now().UTC().Before(dev.TrustedAfter) {
				logger.Warn("checkin from untrusted device", "device_id", did, "trusted_after", dev.TrustedAfter)
				httpError(w, http.StatusForbidden, "device in delayed-trust window")
				return
			}
			var nonce [checkin.NonceSize]byte
			copy(nonce[:], nonceB)
			if _, err := checkin.Verify(req.Context(), ns, nonce, did, uid, body.Counter, sig, dev.DevicePubKey, dev.MonotonicCounter); err != nil {
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
			// Advance all armed policies owned by this user. This runs after
			// the counter/audit tx (each policy advance is its own epoch-CAS
			// tx), so a failure here must surface to the device: the check-in
			// was recorded but deadlines were not (fully) advanced, and the
			// client must retry with a fresh nonce. Retrying is safe —
			// advancing an already-advanced policy just resets its deadline.
			advanced := 0
			if polSvc != nil {
				n, err := polSvc.CheckInAllArmed(req.Context(), uid, &did)
				advanced = n
				if err != nil {
					logger.Error("checkin advance policies", "err", err, "advanced", n)
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"status":            "partial",
						"error":             "check-in recorded but policy deadlines not fully advanced; retry",
						"policies_advanced": advanced,
					})
					return
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":            "ok",
				"policies_advanced": advanced,
			})
		})
	})
}
