package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/store"
)

type createPolicyReq struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	IntervalDays     int      `json:"interval_days"`
	GracePeriodHours int      `json:"grace_period_hours"`
	HoldPeriodHours  int      `json:"hold_period_hours"`
	ReleaseMode      string   `json:"release_mode"`
	DestinationIDs   []string `json:"destination_ids"`
	BundleIDs        []string `json:"bundle_ids"`
	UserSignature    string   `json:"user_signature"` // base64url
}

type policyAction func(ctx context.Context, userID, policyID uuid.UUID) error

func mountPolicyRoutes(r chi.Router, logger *slog.Logger, svc *policy.Service, s *store.Store, authSvc *auth.Service) {
	action := func(fn policyAction) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				httpError(w, http.StatusBadRequest, "bad id")
				return
			}
			if err := fn(req.Context(), uid, id); err != nil {
				logger.Warn("policy action", "policy_id", id, "err", err)
				httpError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}
	}

	r.Route("/policies", func(r chi.Router) {
		r.Use(authSvc.RequireSession)

		r.Post("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			var body createPolicyReq
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			destIDs, err := parseUUIDs(body.DestinationIDs)
			if err != nil {
				httpError(w, http.StatusBadRequest, "bad destination_ids")
				return
			}
			bundleIDs, err := parseUUIDs(body.BundleIDs)
			if err != nil {
				httpError(w, http.StatusBadRequest, "bad bundle_ids")
				return
			}
			var sig []byte
			if body.UserSignature != "" {
				sig, err = base64.RawURLEncoding.DecodeString(body.UserSignature)
				if err != nil {
					httpError(w, http.StatusBadRequest, "bad user_signature")
					return
				}
			}
			p, v, err := svc.Create(req.Context(), policy.CreateInput{
				UserID:           uid,
				Title:            body.Title,
				Description:      body.Description,
				IntervalDays:     body.IntervalDays,
				GracePeriodHours: body.GracePeriodHours,
				HoldPeriodHours:  body.HoldPeriodHours,
				ReleaseMode:      body.ReleaseMode,
				DestinationIDs:   destIDs,
				BundleIDs:        bundleIDs,
				UserSignature:    sig,
			})
			if err != nil {
				logger.Error("create policy", "err", err)
				httpError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{
				"id":         p.ID,
				"state":      p.State,
				"version":    v.Version,
				"version_id": v.ID,
			})
		})

		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			ps, err := store.ListUserPolicies(req.Context(), s.Pool, uid)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "list failed")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"policies": ps})
		})

		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				uid, _ := auth.UserFromContext(req.Context())
				id, err := uuid.Parse(chi.URLParam(req, "id"))
				if err != nil {
					httpError(w, http.StatusBadRequest, "bad id")
					return
				}
				p, err := store.GetPolicy(req.Context(), s.Pool, id)
				if err != nil || p.UserID != uid {
					httpError(w, http.StatusNotFound, "not found")
					return
				}
				ps, _ := store.GetPolicyState(req.Context(), s.Pool, id)
				writeJSON(w, http.StatusOK, map[string]any{"policy": p, "runtime": ps})
			})
			r.Post("/arm", action(svc.Arm))
			r.Post("/suspend", action(svc.Suspend))
			r.Post("/resume", action(svc.Resume))
			r.Post("/revoke", action(svc.Revoke))
		})
	})
}

func parseUUIDs(ss []string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(ss))
	for _, s := range ss {
		u, err := uuid.Parse(s)
		if err != nil {
			return nil, errors.New("uuid parse: " + s)
		}
		out = append(out, u)
	}
	return out, nil
}
