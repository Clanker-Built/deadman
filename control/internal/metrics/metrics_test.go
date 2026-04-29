package metrics

import (
	"testing"
	"time"
)

func TestRegistry_RequestAndCounters(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 100; i++ {
		r.ObserveRequest("GET", "/x", 200, time.Duration(i+1)*time.Millisecond)
	}
	r.ObserveRequest("GET", "/x", 500, 10*time.Millisecond)

	s := r.Snapshot()
	if s.Counters["http.requests"] != 101 {
		t.Fatalf("requests: %d", s.Counters["http.requests"])
	}
	if s.Counters["http.5xx"] != 1 {
		t.Fatalf("5xx: %d", s.Counters["http.5xx"])
	}
	if len(s.Routes) != 1 {
		t.Fatalf("routes: %+v", s.Routes)
	}
	rs := s.Routes[0]
	if rs.Count != 101 || rs.P50ms <= 0 || rs.P95ms < rs.P50ms {
		t.Fatalf("route stat wrong: %+v", rs)
	}
}

func TestRegistry_EventRate(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 5; i++ {
		r.Event("release.completed")
	}
	s := r.Snapshot()
	rate := s.Rates["release.completed"]
	if rate.Last1m != 5 || rate.Total != 5 {
		t.Fatalf("rate: %+v", rate)
	}
}

func TestHistogram_Reservoir(t *testing.T) {
	h := newHistogram()
	for i := 0; i < reservoirSize*3; i++ {
		h.observe(time.Duration(i) * time.Millisecond)
	}
	if h.count != int64(reservoirSize*3) {
		t.Fatalf("count: %d", h.count)
	}
	if len(h.samples) != reservoirSize {
		t.Fatalf("samples: %d", len(h.samples))
	}
	p := h.percentiles()
	if p.max < p.p99 || p.p99 < p.p50 {
		t.Fatalf("percentile order: %+v", p)
	}
}
