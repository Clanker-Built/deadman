package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
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
	Admin      *admin.Deps
	AdminMount *admin.MountConfig

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
	r.Use(middleware.Recoverer)
	// 256 MiB bundle uploads over a slow Tor circuit legitimately take far
	// longer than the global 20s budget; give that one route its own window.
	r.Use(timeoutExcept(20*time.Second, time.Hour, isBundleUpload))
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
			mountReleaseKeyRoute(r, pub)
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

// isBundleUpload reports whether the request is the large-bundle upload
// (POST /api/v1/bundles), which is excluded from the global timeout. The
// handler still bounds the body with MaxBytesReader and a per-user rate
// limit, and ReadHeaderTimeout still applies before routing.
func isBundleUpload(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		strings.TrimSuffix(r.URL.Path, "/") == "/api/v1/bundles"
}

// timeoutExcept applies the standard request timeout to every route except
// those matched by skip, which get the longer window instead. For skipped
// requests the connection read/write deadlines are extended to match: the
// http.Server's 30s Read/WriteTimeout would otherwise sever a slow upload
// mid-body regardless of what the handler context allows.
func timeoutExcept(std, long time.Duration, skip func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		stdTimed := middleware.Timeout(std)(next)
		longTimed := middleware.Timeout(long)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip(r) {
				deadline := time.Now().Add(long)
				rc := http.NewResponseController(w)
				_ = rc.SetReadDeadline(deadline)
				_ = rc.SetWriteDeadline(deadline)
				longTimed.ServeHTTP(w, r)
				return
			}
			stdTimed.ServeHTTP(w, r)
		})
	}
}
