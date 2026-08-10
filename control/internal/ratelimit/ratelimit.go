// Package ratelimit provides a small keyed token-bucket limiter plus HTTP
// middleware factories.
//
// Design:
//   - In-memory per-process. When we go multi-process (M5+) swap the Bucket
//     map for a Redis INCR+EXPIRE-backed store; the public API stays stable.
//   - Per-key: one golang.org/x/time/rate.Limiter per key, created lazily,
//     garbage-collected after StaleAfter of inactivity.
//   - Key extraction is left to the caller (IP, user ID, device ID, or a
//     composite). Per-route policy is built by composing limiters.
//
// Tor reality: all exit IPs share traffic; per-IP limits must be generous
// (or skipped entirely for static routes). Per-account / per-device limits
// are the real protection.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token-bucket. Zero value is not usable; call New.
type Limiter struct {
	rate       rate.Limit
	burst      int
	staleAfter time.Duration
	mu         sync.Mutex
	buckets    map[string]*entry
}

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// New constructs a Limiter. ratePerSecond is the steady-state refill rate
// (tokens/sec). burst is the bucket capacity. staleAfter is how long an
// idle key is retained before GC.
func New(ratePerSecond float64, burst int, staleAfter time.Duration) *Limiter {
	if staleAfter == 0 {
		staleAfter = 10 * time.Minute
	}
	l := &Limiter{
		rate:       rate.Limit(ratePerSecond),
		burst:      burst,
		staleAfter: staleAfter,
		buckets:    make(map[string]*entry),
	}
	go l.gcLoop()
	return l
}

// Allow returns true if a token is available for this key.
func (l *Limiter) Allow(key string) bool {
	if key == "" {
		return true // no key = don't attempt limiting; caller decision
	}
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxKeys {
			l.evictOneLocked()
		}
		e = &entry{lim: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[key] = e
	}
	e.lastSeen = time.Now()
	l.mu.Unlock()
	return e.lim.Allow()
}

func (l *Limiter) gcLoop() {
	t := time.NewTicker(l.staleAfter)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-l.staleAfter)
		l.mu.Lock()
		for k, e := range l.buckets {
			if e.lastSeen.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// KeyFunc extracts a limiting key from a request.
type KeyFunc func(r *http.Request) string

// ClientIP returns the host part of the connection's RemoteAddr.
// X-Forwarded-For is deliberately ignored: this server terminates client
// connections itself (Tor .onion / direct listener), so any forwarding
// header is attacker-supplied and would let a client mint a fresh
// rate-limit bucket per request. If a trusted reverse proxy is ever put
// in front, gate header parsing on an explicit trusted-proxy allowlist
// rather than re-enabling unconditional trust.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware wraps an http.Handler with a limiter. Returns 429 when denied,
// with a minimal JSON body and a Retry-After hint of 60s. The hint is not
// precise — the caller just needs to back off.
func Middleware(l *Limiter, key KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k := key(r)
			if k != "" && !l.Allow(k) {
				w.Header().Set("Retry-After", "60")
				// Browser (/ui/) requests get a readable HTML page; API
				// clients get JSON. Raw JSON on the login screen reads as a
				// scary error to a stressed non-technical user.
				if strings.HasPrefix(r.URL.Path, "/ui/") {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(rateLimitedHTML))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Composite applies multiple limiters; first to deny wins.
func Composite(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		h := next
		for i := len(mws) - 1; i >= 0; i-- {
			h = mws[i](h)
		}
		return h
	}
}

// maxKeys caps the bucket map so attacker-minted keys (spoofed addresses,
// invented emails) cannot grow memory without bound between GC sweeps.
// When full, an approximately-stalest entry is evicted.
const maxKeys = 65536

// evictOneLocked deletes the stalest entry among a small random sample.
// Caller must hold l.mu. Sampling keeps eviction O(1); Go map iteration
// order is randomized, so repeated calls touch different entries.
func (l *Limiter) evictOneLocked() {
	var oldestKey string
	var oldestSeen time.Time
	n := 0
	for k, e := range l.buckets {
		if n == 0 || e.lastSeen.Before(oldestSeen) {
			oldestKey, oldestSeen = k, e.lastSeen
		}
		n++
		if n >= 16 {
			break
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

// rateLimitedHTML is the /ui/ 429 body. It links the same-origin stylesheet
// (allowed by CSP 'self') and contains no inline styles or scripts.
const rateLimitedHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Too many attempts — Deadman</title>
<link rel="stylesheet" href="/ui/static/style.css"></head>
<body><header><nav><strong>Deadman</strong></nav></header>
<main><section><h1>Too many attempts</h1>
<p class="muted">You have made too many requests in a short window. This is a
safety limit that protects accounts from automated guessing.</p>
<p>Please wait about a minute, then <a href="/ui/login">try again</a>.</p>
</section></main></body></html>`
