// Package metrics is an in-process metrics surface: counters and lightweight
// latency histograms kept in a sliding window. No external dependencies,
// no Prometheus — deliberately scoped to what a solo operator actually
// wants to read from an admin page.
//
// Thread-safe. Costs: O(1) per Observe/Inc, O(routes) memory.
package metrics

import (
	"sort"
	"sync"
	"time"
)

// Registry is the process-wide metrics aggregator. Constructed once at
// startup; every middleware and worker writes into it.
type Registry struct {
	mu sync.RWMutex

	// Rolling per-route latency histograms, keyed by "method path".
	routes map[string]*histogram

	// Simple monotonic counters keyed by string name. Interpretation is
	// the caller's — e.g. "release.completed", "rate_limit.rejected".
	counters map[string]int64

	// Event log for rate-based views: circular buffer of timestamped
	// events by kind. Used to compute "last N minutes" rates.
	events map[string]*ringBuf
}

// NewRegistry returns an empty, ready-to-use registry.
func NewRegistry() *Registry {
	return &Registry{
		routes:   make(map[string]*histogram),
		counters: make(map[string]int64),
		events:   make(map[string]*ringBuf),
	}
}

// ObserveRequest records a finished HTTP request.
func (r *Registry) ObserveRequest(method, route string, status int, dur time.Duration) {
	key := method + " " + route
	r.mu.Lock()
	h, ok := r.routes[key]
	if !ok {
		h = newHistogram()
		r.routes[key] = h
	}
	h.observe(dur)
	r.mu.Unlock()
	// Track 5xx as a separate counter so the dashboard can show "errors".
	if status >= 500 {
		r.Inc("http.5xx")
	}
	r.Inc("http.requests")
}

// Inc adds 1 to the named counter.
func (r *Registry) Inc(name string) { r.Add(name, 1) }

// Add adds n to the named counter.
func (r *Registry) Add(name string, n int64) {
	r.mu.Lock()
	r.counters[name] += n
	r.mu.Unlock()
}

// Event records a timestamped event of the given kind, for rate-over-time
// views. kinds with no events are not tracked until their first RecordEvent.
func (r *Registry) Event(kind string) {
	r.mu.Lock()
	rb, ok := r.events[kind]
	if !ok {
		rb = newRingBuf(4096) // ~1 per second for an hour
		r.events[kind] = rb
	}
	rb.push(time.Now())
	r.mu.Unlock()
}

// --- Snapshot types ---

// Snapshot is a copy of all metrics for rendering. Safe to ship to the
// admin template; never reference the internal histograms directly.
type Snapshot struct {
	Routes     []RouteStat
	Counters   map[string]int64
	Rates      map[string]EventRate // keyed by kind
	CapturedAt time.Time
}

// RouteStat is per-route aggregate.
type RouteStat struct {
	Route string
	Count int64
	P50ms int64
	P95ms int64
	P99ms int64
	MaxMs int64
}

// EventRate summarizes events-per-minute over several windows.
type EventRate struct {
	Last1m  int64
	Last5m  int64
	Last60m int64
	Total   int64
}

// Snapshot takes a point-in-time read.
func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snap := Snapshot{
		CapturedAt: time.Now().UTC(),
		Counters:   make(map[string]int64, len(r.counters)),
		Rates:      make(map[string]EventRate, len(r.events)),
	}
	for k, v := range r.counters {
		snap.Counters[k] = v
	}
	now := time.Now()
	for k, rb := range r.events {
		snap.Rates[k] = EventRate{
			Last1m:  rb.countSince(now.Add(-1 * time.Minute)),
			Last5m:  rb.countSince(now.Add(-5 * time.Minute)),
			Last60m: rb.countSince(now.Add(-60 * time.Minute)),
			Total:   rb.total,
		}
	}
	routes := make([]RouteStat, 0, len(r.routes))
	for k, h := range r.routes {
		p := h.percentiles()
		routes = append(routes, RouteStat{
			Route: k, Count: h.count,
			P50ms: p.p50.Milliseconds(),
			P95ms: p.p95.Milliseconds(),
			P99ms: p.p99.Milliseconds(),
			MaxMs: p.max.Milliseconds(),
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Count != routes[j].Count {
			return routes[i].Count > routes[j].Count
		}
		return routes[i].Route < routes[j].Route
	})
	snap.Routes = routes
	return snap
}

// --- histogram ---

// histogram keeps reservoir samples of recent observations. Not a perfect
// statistical histogram, but adequate for an operator dashboard: 512 most
// recent samples per route, plus running max and count. Good enough for
// P50/P95/P99 on any normal-traffic solo deployment.
const reservoirSize = 512

type histogram struct {
	samples []time.Duration
	count   int64
	max     time.Duration
	next    int
}

func newHistogram() *histogram {
	return &histogram{samples: make([]time.Duration, 0, reservoirSize)}
}

func (h *histogram) observe(d time.Duration) {
	h.count++
	if d > h.max {
		h.max = d
	}
	if len(h.samples) < reservoirSize {
		h.samples = append(h.samples, d)
		return
	}
	h.samples[h.next] = d
	h.next = (h.next + 1) % reservoirSize
}

type pct struct {
	p50, p95, p99, max time.Duration
}

func (h *histogram) percentiles() pct {
	if len(h.samples) == 0 {
		return pct{}
	}
	sorted := make([]time.Duration, len(h.samples))
	copy(sorted, h.samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(q float64) time.Duration {
		idx := int(float64(len(sorted)-1) * q)
		return sorted[idx]
	}
	return pct{
		p50: pick(0.50),
		p95: pick(0.95),
		p99: pick(0.99),
		max: h.max,
	}
}

// --- ringBuf ---

// ringBuf stores event timestamps. countSince scans back until it hits the
// cutoff; O(N) in the worst case but N is bounded by capacity.
type ringBuf struct {
	ts    []time.Time
	cap   int
	next  int
	total int64
}

func newRingBuf(capacity int) *ringBuf {
	return &ringBuf{ts: make([]time.Time, 0, capacity), cap: capacity}
}

func (r *ringBuf) push(t time.Time) {
	r.total++
	if len(r.ts) < r.cap {
		r.ts = append(r.ts, t)
		return
	}
	r.ts[r.next] = t
	r.next = (r.next + 1) % r.cap
}

func (r *ringBuf) countSince(cutoff time.Time) int64 {
	var n int64
	for _, t := range r.ts {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}
