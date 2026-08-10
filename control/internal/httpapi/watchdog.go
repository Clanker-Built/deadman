package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
)

// Watchdog state is maintained in memory — the scheduler ticks this on each
// loop so an external verifier can probe /watchdog and detect silence.
type Watchdog struct {
	servicePub  ed25519.PublicKey
	servicePriv ed25519.PrivateKey
	// lastTickNanos is the last tick as Unix nanoseconds (0 = never).
	// Atomic: written by the scheduler goroutine, read by HTTP handlers.
	lastTickNanos atomic.Int64
}

// NewWatchdog returns a watchdog that signs heartbeats with the given key.
func NewWatchdog(pub ed25519.PublicKey, priv ed25519.PrivateKey) *Watchdog {
	return &Watchdog{servicePub: pub, servicePriv: priv}
}

// Tick is called by the scheduler on each loop iteration.
func (w *Watchdog) Tick() { w.lastTickNanos.Store(time.Now().UnixNano()) }

// LastTick returns the most recent tick time (zero if never ticked).
func (w *Watchdog) LastTick() time.Time {
	n := w.lastTickNanos.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// mountWatchdogRoute exposes an unauthenticated signed heartbeat.
//
// Design: the response carries the public key, last tick, current time, and
// an Ed25519 signature over a canonical concatenation. An independent prober
// (Cloudflare Worker cron) verifies the signature and the recency and pages
// a human if lastTick is stale.
//
// Why public: verifiers are outside our trust boundary by design (the whole
// point is to detect our own silent failure). The only information leaked
// is "service is alive" which is exactly what we want to publish.
func mountWatchdogRoute(r chi.Router, w *Watchdog) {
	r.Get("/watchdog", func(rw http.ResponseWriter, _ *http.Request) {
		now := time.Now().UTC()
		var lastMs int64
		if last := w.LastTick(); !last.IsZero() {
			lastMs = last.UnixMilli()
		}
		// Canonical payload: "deadman-watchdog|<now_ms>|<last_ms>"
		payload := []byte("deadman-watchdog|" +
			itoa(now.UnixMilli()) + "|" + itoa(lastMs))
		sig := ed25519.Sign(w.servicePriv, payload)
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"now_ms":            now.UnixMilli(),
			"last_scheduler_ms": lastMs,
			"service_pubkey":    base64.RawURLEncoding.EncodeToString(w.servicePub),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"payload":           string(payload),
		})
	})
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
