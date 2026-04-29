package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/gcottrell/deadman/control/internal/admin"
	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/checkin"
	"github.com/gcottrell/deadman/control/internal/metrics"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
	"github.com/gcottrell/deadman/control/internal/webui"
)

// rsaPubKey is a type alias so the Deps field can hold an rsa.PublicKey
// without every test or importer needing to import crypto/rsa.
type rsaPubKey = rsa.PublicKey

// Deps bundles everything the HTTP layer needs. Nil fields mean that feature
// is disabled — e.g. tests may pass only Logger.
type Deps struct {
	Logger        *slog.Logger
	Store         *store.Store
	Auth          *auth.Service
	Ledger        *audit.Ledger
	Nonces        *checkin.Store
	Policy        *policy.Service
	WebUI         *webui.Renderer
	Storage       *storage.DualWriter
	Watchdog      *Watchdog
	ReleasePubKey interface{} // *rsa.PublicKey; kept loose to avoid extra import at test sites
	DevMode       bool

	// Admin enables the /ui/admin/* surface when non-nil.
	Admin       *admin.Deps
	AdminMount  *admin.MountConfig

	// Metrics: when non-nil, every request is recorded to this registry.
	Metrics *metrics.Registry

	// Auth pivot: passphrase + TOTP path needs these to mirror the values
	// already given to auth.Service so the bootstrap-admin promotion and
	// otpauth issuer name stay consistent.
	BootstrapAdminEmail string
	RPDisplayName       string
}

// NewRouter wires the HTTP surface. Preserved as the zero-dependency form
// used by the M0 smoke tests; use NewRouterWithDeps for wired-up stacks.
func NewRouter(logger *slog.Logger) http.Handler {
	return NewRouterWithDeps(Deps{Logger: logger})
}

func NewRouterWithDeps(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(20 * time.Second))
	r.Use(securityHeaders)
	if d.Metrics != nil {
		r.Use(metricsMiddleware(d.Metrics))
	}
	if d.Auth != nil {
		r.Use(csrfMiddleware(d.Auth))
	}

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if d.Store != nil {
			ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
			defer cancel()
			if err := d.Store.Pool.Ping(ctx); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"status": "not_ready", "error": err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"pong": "true"})
		})
		if pub, ok := d.ReleasePubKey.(*rsaPubKey); ok && pub != nil {
			mountReleaseKeyRoute(r, (*rsa.PublicKey)(pub))
		}
		if d.Auth != nil {
			mountAuthRoutes(r, d.Logger, d.Auth)
		}
		if d.Auth != nil && d.Store != nil && d.Ledger != nil {
			mountDeviceRoutes(r, d.Logger, d.Store, d.Auth, d.Ledger)
		}
		if d.Auth != nil && d.Store != nil && d.Ledger != nil && d.Nonces != nil {
			mountCheckinRoutes(r, d.Logger, d.Store, d.Auth, d.Ledger, d.Nonces, d.Policy)
		}
		if d.Auth != nil && d.Store != nil && d.Policy != nil {
			mountPolicyRoutes(r, d.Logger, d.Policy, d.Store, d.Auth)
		}
		if d.Auth != nil && d.Store != nil && d.Ledger != nil && d.Storage != nil {
			mountBundleRoutes(r, d.Logger, d.Store, d.Auth, d.Ledger, d.Storage)
		}
	})

	if d.Watchdog != nil {
		mountWatchdogRoute(r, d.Watchdog)
	}

	if d.WebUI != nil && d.Auth != nil && d.Store != nil && d.Policy != nil {
		if err := webui.MountWithConfig(r, d.Logger, d.Store, d.Auth, d.Policy, d.WebUI, webui.MountConfig{
			DevMode:             d.DevMode,
			BootstrapAdminEmail: d.BootstrapAdminEmail,
			RPDisplayName:       d.RPDisplayName,
		}); err != nil {
			d.Logger.Error("webui mount", "err", err)
		}
		if d.Admin != nil && d.AdminMount != nil {
			d.Admin.Mount(r, *d.AdminMount)
		}
	}

	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
