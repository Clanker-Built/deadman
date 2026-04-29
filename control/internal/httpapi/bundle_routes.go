package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/ratelimit"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// Bundle upload limits. Per-user quota enforcement lands in M4.
const maxBundleSize = 256 * 1024 * 1024 // 256 MiB

type uploadBundleReq struct {
	Label            string `json:"label,omitempty"`
	Ciphertext       string `json:"ciphertext"`
	ManifestHash     string `json:"manifest_hash"`      // base64url SHA-256 of the manifest
	Manifest         string `json:"manifest,omitempty"` // base64url manifest JSON bytes (bound as AAD); opaque to server
	WrappedBundleKey string `json:"wrapped_bundle_key"` // base64url
	WrapScheme       string `json:"wrap_scheme"`        // e.g. "rsa-oaep-sha256.aes-gcm.v1"
}

// mountBundleRoutes exposes /api/v1/bundles. Payload is rejected if it's
// not obviously opaque bytes; the server never decrypts here.
func mountBundleRoutes(r chi.Router, logger *slog.Logger, s *store.Store, authSvc *auth.Service, ledger *audit.Ledger, dw *storage.DualWriter) {
	// Per-user: ~40 uploads/day (rate 0.0005/s = 1 per 33 min, burst 10).
	// Plenty for legit use; stops a compromised session from flooding.
	perUserUpload := ratelimit.New(0.0005, 10, time.Hour)
	userKey := func(r *http.Request) string {
		if uid, ok := auth.UserFromContext(r.Context()); ok {
			return "user:" + uid.String()
		}
		return ""
	}
	limitUpload := ratelimit.Middleware(perUserUpload, userKey)

	r.Route("/bundles", func(r chi.Router) {
		r.Use(authSvc.RequireSession)

		r.With(limitUpload).Post("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			req.Body = http.MaxBytesReader(w, req.Body, maxBundleSize+1024)
			var body uploadBundleReq
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				httpError(w, http.StatusBadRequest, "invalid json")
				return
			}
			ct, err := base64.RawURLEncoding.DecodeString(body.Ciphertext)
			if err != nil || len(ct) == 0 {
				httpError(w, http.StatusBadRequest, "ciphertext must be base64url and non-empty")
				return
			}
			if int64(len(ct)) > maxBundleSize {
				httpError(w, http.StatusRequestEntityTooLarge, "bundle too large")
				return
			}
			mh, err := base64.RawURLEncoding.DecodeString(body.ManifestHash)
			if err != nil || len(mh) != 32 {
				httpError(w, http.StatusBadRequest, "manifest_hash must be base64url 32 bytes")
				return
			}
			var manifestBytes []byte
			if body.Manifest != "" {
				manifestBytes, err = base64.RawURLEncoding.DecodeString(body.Manifest)
				if err != nil {
					httpError(w, http.StatusBadRequest, "manifest must be base64url")
					return
				}
			}
			wk, err := base64.RawURLEncoding.DecodeString(body.WrappedBundleKey)
			if err != nil || len(wk) == 0 {
				httpError(w, http.StatusBadRequest, "wrapped_bundle_key required")
				return
			}
			if body.WrapScheme == "" {
				httpError(w, http.StatusBadRequest, "wrap_scheme required")
				return
			}

			id := uuid.New()
			key := "bundles/" + uid.String() + "/" + id.String() + ".bin"

			wr, err := dw.Put(req.Context(), key, ct, "application/octet-stream")
			if err != nil {
				logger.Error("bundle primary write", "err", err)
				httpError(w, http.StatusBadGateway, "storage write failed")
				return
			}

			digest := sha256.Sum256(ct)
			var backupURI *string
			if wr.BackupURI != "" {
				s := wr.BackupURI
				backupURI = &s
			}

			var inserted *store.ContentBundle
			txErr := s.InTx(req.Context(), func(ctx context.Context, q store.Querier) error {
				b := &store.ContentBundle{
					UserID:           uid,
					Version:          1,
					Label:            body.Label,
					ManifestHash:     mh,
					Manifest:         manifestBytes,
					WrappedBundleKey: wk,
					WrapScheme:       body.WrapScheme,
					PrimaryURI:       wr.PrimaryURI,
					BackupURI:        backupURI,
					SizeBytes:        int64(len(ct)),
					CiphertextSHA256: digest[:],
				}
				// Force the generated id so the storage key and DB row match.
				b.ID = id
				got, err := insertBundleWithID(ctx, q, b)
				if err != nil {
					return err
				}
				inserted = got
				_, err = ledger.AppendTx(ctx, q, audit.Event{
					ActorKind:   audit.ActorUser,
					ActorID:     &uid,
					EventType:   "bundle.uploaded",
					SubjectKind: "bundle",
					SubjectID:   &id,
					Payload: map[string]any{
						"size_bytes":   len(ct),
						"wrap_scheme":  body.WrapScheme,
						"primary_uri":  wr.PrimaryURI,
						"backup_ok":    wr.BackupURI != "",
						"ciphertext_sha256": base64.RawURLEncoding.EncodeToString(digest[:]),
					},
				})
				return err
			})
			if txErr != nil {
				logger.Error("bundle db write", "err", txErr)
				httpError(w, http.StatusInternalServerError, "db write failed")
				return
			}

			writeJSON(w, http.StatusCreated, map[string]any{
				"id":           inserted.ID,
				"size_bytes":   inserted.SizeBytes,
				"primary_uri":  inserted.PrimaryURI,
				"backup_uri":   inserted.BackupURI,
				"backup_ok":    wr.BackupURI != "",
				"backup_error": errString(wr.BackupErr),
			})
		})

		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			uid, _ := auth.UserFromContext(req.Context())
			bs, err := store.ListUserBundles(req.Context(), s.Pool, uid)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "list failed")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"bundles": bs})
		})
	})
	_ = io.Discard
}

// insertBundleWithID is a variant that honors a caller-provided ID so the
// object-storage key matches the DB row.
func insertBundleWithID(ctx context.Context, q store.Querier, b *store.ContentBundle) (*store.ContentBundle, error) {
	var out store.ContentBundle
	err := q.QueryRow(ctx,
		`INSERT INTO content_bundles
		   (id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		    primary_uri, backup_uri, size_bytes, ciphertext_sha256)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		           primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at`,
		b.ID, b.UserID, b.Version, b.Label, b.ManifestHash, b.Manifest, b.WrappedBundleKey, b.WrapScheme,
		b.PrimaryURI, b.BackupURI, b.SizeBytes, b.CiphertextSHA256,
	).Scan(&out.ID, &out.UserID, &out.Version, &out.Label, &out.ManifestHash, &out.Manifest, &out.WrappedBundleKey, &out.WrapScheme,
		&out.PrimaryURI, &out.BackupURI, &out.SizeBytes, &out.CiphertextSHA256, &out.CreatedAt, &out.DeletedAt)
	return &out, err
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
