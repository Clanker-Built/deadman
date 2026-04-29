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

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/store"
)

// TrustDelay is the delayed-trust window after enrollment. Freshly enrolled
// devices cannot perform sensitive actions (arm a policy, check in on behalf
// of a not-yet-trusted policy) until elapsed. Prevents a stolen-device
// attacker who also has the passkey from immediately controlling the switch.
const TrustDelay = 24 * time.Hour

type enrollReq struct {
	Platform      string `json:"platform"` // "android" | "ios"
	Nickname      string `json:"nickname"`
	DevicePubKey  string `json:"device_pubkey"` // base64-raw-url Ed25519 public key
	Attestation   string `json:"attestation,omitempty"`
	PushToken     string `json:"push_token,omitempty"`
	PushTokenKind string `json:"push_token_kind,omitempty"`
}

func mountDeviceRoutes(r chi.Router, logger *slog.Logger, s *store.Store, authSvc *auth.Service, ledger *audit.Ledger) {
	r.Route("/devices", func(r chi.Router) {
		r.Use(authSvc.RequireSession)

		r.Post("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			var body enrollReq
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			if body.Platform != "android" && body.Platform != "ios" {
				httpError(w, http.StatusBadRequest, "platform must be android or ios")
				return
			}
			pub, err := base64.RawURLEncoding.DecodeString(body.DevicePubKey)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				httpError(w, http.StatusBadRequest, "device_pubkey must be base64url Ed25519 (32B)")
				return
			}
			var attest []byte
			if body.Attestation != "" {
				attest, err = base64.RawURLEncoding.DecodeString(body.Attestation)
				if err != nil {
					httpError(w, http.StatusBadRequest, "attestation must be base64url")
					return
				}
			}

			var created *store.Device
			txErr := s.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
				d := &store.Device{
					UserID:       uid,
					Platform:     body.Platform,
					Nickname:     body.Nickname,
					DevicePubKey: pub,
					Attestation:  attest,
					TrustedAfter: time.Now().UTC().Add(TrustDelay),
				}
				if body.PushToken != "" {
					d.PushToken = &body.PushToken
				}
				if body.PushTokenKind != "" {
					d.PushTokenKind = &body.PushTokenKind
				}
				inserted, err := store.CreateDevice(ctx, q, d)
				if err != nil {
					return err
				}
				created = inserted
				_, err = ledger.AppendTx(ctx, q, audit.Event{
					ActorKind:   audit.ActorUser,
					ActorID:     &uid,
					EventType:   "device.enrolled",
					SubjectKind: "device",
					SubjectID:   &inserted.ID,
					Payload: map[string]any{
						"platform":      body.Platform,
						"trusted_after": inserted.TrustedAfter,
					},
				})
				return err
			})
			if txErr != nil {
				logger.Error("device enroll", "err", txErr)
				httpError(w, http.StatusInternalServerError, "enrollment failed")
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{
				"id":            created.ID,
				"platform":      created.Platform,
				"nickname":      created.Nickname,
				"trusted_after": created.TrustedAfter,
				"created_at":    created.CreatedAt,
			})
		})

		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			devs, err := store.ListUserDevices(req.Context(), s.Pool, uid)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "list devices failed")
				return
			}
			out := make([]map[string]any, 0, len(devs))
			for _, d := range devs {
				out = append(out, map[string]any{
					"id":            d.ID,
					"platform":      d.Platform,
					"nickname":      d.Nickname,
					"trusted_after": d.TrustedAfter,
					"last_seen_at":  d.LastSeenAt,
					"created_at":    d.CreatedAt,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{"devices": out})
		})
	})
}
