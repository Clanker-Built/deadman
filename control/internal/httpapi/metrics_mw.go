package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/gcottrell/deadman/control/internal/metrics"
)

// metricsMiddleware records each request's method, chi routing pattern,
// status code, and duration to the registry. We key on the pattern
// (`/api/v1/auth/login/begin`) rather than the full path, so metrics
// aggregate cleanly across users.
func metricsMiddleware(reg *metrics.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)
			pattern := chi.RouteContext(r.Context()).RoutePattern()
			if pattern == "" {
				pattern = "(unknown)"
			}
			reg.ObserveRequest(r.Method, pattern, rec.status, time.Since(start))
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true // implicit 200
	}
	return r.ResponseWriter.Write(b)
}
