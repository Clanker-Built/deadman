package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gcottrell/deadman/control/internal/webui"
)

// CSPNonceKey returns the context key that carries the CSP nonce.
// Exposed so tests and the webui package can read it via the same key.
func CSPNonceKey() any { return webui.NonceKey() }

// securityHeaders applies hardening appropriate for a whistle-blower-grade
// deployment: strict CSP with per-request nonces (no 'unsafe-inline'),
// HSTS, no referrer, frame denial, Permissions-Policy lockdown, and
// cache-control tuned for authed pages.
//
// Tor Browser friendly:
//   - no third-party origins
//   - no remote fonts/scripts
//   - JS only from 'self' with a per-request nonce (so CSP level 3 hosts
//     can still run the WebAuthn ceremony script)
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nb := make([]byte, 16)
		_, _ = rand.Read(nb)
		// URL-safe base64 avoids HTML-escape ambiguity on `+` / `/` in attrs.
		nonce := base64.RawURLEncoding.EncodeToString(nb)

		h := w.Header()
		// Content Security Policy — no inline-unsafe, no third-party origins.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'nonce-"+nonce+"'; "+
				"style-src 'self' 'nonce-"+nonce+"'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"object-src 'none'; "+
				"upgrade-insecure-requests")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Permissions-Policy",
			"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
				"magnetometer=(), microphone=(), payment=(), usb=(), "+
				"publickey-credentials-get=(self), publickey-credentials-create=(self)")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		ctx := context.WithValue(r.Context(), webui.NonceKey(), nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
