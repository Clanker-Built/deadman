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

// ClientIP extracts a remote-addr, honoring X-Forwarded-For's LAST hop (the
// one we trust — our own reverse proxy). Falls back to RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
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
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
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
