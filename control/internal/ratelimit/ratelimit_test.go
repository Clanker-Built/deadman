package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllowRate(t *testing.T) {
	l := New(1, 2, time.Minute) // 1 rps, burst 2
	ok := 0
	for i := 0; i < 5; i++ {
		if l.Allow("ip-a") {
			ok++
		}
	}
	if ok < 2 || ok > 3 {
		t.Fatalf("expected ~2 allowed out of 5 under 1rps/burst2, got %d", ok)
	}
}

func TestDifferentKeysIndependent(t *testing.T) {
	l := New(1, 1, time.Minute)
	if !l.Allow("a") {
		t.Fatal("first allow on a failed")
	}
	if !l.Allow("b") {
		t.Fatal("first allow on b should succeed — independent bucket")
	}
	if l.Allow("a") {
		t.Fatal("second a should be denied")
	}
}

func TestMiddleware429(t *testing.T) {
	l := New(0.01, 1, time.Minute) // effectively 1 request ever in test window
	h := Middleware(l, func(r *http.Request) string { return "x" })(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) },
	))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("first want 200 got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 429 {
		t.Fatalf("second want 429 got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}
