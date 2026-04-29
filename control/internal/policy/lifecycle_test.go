package policy_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/scheduler"
	"github.com/gcottrell/deadman/control/internal/store"
)

// fakeClock is an injectable clock that the scheduler advances in ms.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func requireStore(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DEADMAN_DATABASE_URL")
	}
	if url == "" {
		t.Skip("no DB url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestCompressedLifecycle: arm a 14-day policy at t0, advance the injected
// clock past each deadline, run scheduler ticks, and assert the state moves
// Healthy → Warning → Grace → Triggered. Verifies DB persistence, audit
// events, and scheduler selection all agree.
func TestCompressedLifecycle(t *testing.T) {
	s := requireStore(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(priv)

	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := policy.New(s, ledger, clk)
	sched := scheduler.New(scheduler.Config{Interval: time.Hour, BatchSize: 100}, svc, s, nil)

	// Seed user.
	email := "life-" + uuid.NewString() + "@test.local"
	var userID uuid.UUID
	err := s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, e := store.CreateUser(ctx, q, email, "Lifecycle", nil)
		if e == nil {
			userID = u.ID
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	// Create policy.
	p, _, err := svc.Create(ctx, policy.CreateInput{
		UserID:           userID,
		Title:            "lifecycle test",
		IntervalDays:     14,
		GracePeriodHours: 72,
		HoldPeriodHours:  48,
		ReleaseMode:      "private",
		UserSignature:    make([]byte, ed25519.SignatureSize),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Arm.
	if err := svc.Arm(ctx, userID, p.ID); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "healthy")

	// Just before warning window — still healthy.
	clk.Advance(14*24*time.Hour - 25*time.Hour)
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "healthy")

	// Inside warning window — Warning.
	clk.Advance(2 * time.Hour) // now: due - 23h
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "warning")

	// Past due — Grace.
	clk.Advance(24 * time.Hour) // now: due + 1h
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "grace")

	// Past grace — Triggered.
	clk.Advance(73 * time.Hour)
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "triggered")

	// Audit: must have a chain of policy.state_transition events for this policy.
	var transitions int
	err = s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		 WHERE event_type = 'policy.state_transition' AND subject_id = $1`, p.ID,
	).Scan(&transitions)
	if err != nil {
		t.Fatal(err)
	}
	if transitions < 4 { // armed→healthy, healthy→warning, warning→grace, grace→triggered
		t.Fatalf("want ≥4 transitions logged, got %d", transitions)
	}
}

// TestCheckInResetsDeadline: the complement — a user who checks in during
// warning returns to healthy and pushes the deadline out.
func TestCheckInResetsDeadline(t *testing.T) {
	s := requireStore(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(priv)
	clk := &fakeClock{now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	svc := policy.New(s, ledger, clk)
	sched := scheduler.New(scheduler.Config{Interval: time.Hour}, svc, s, nil)

	email := "checkin-reset-" + uuid.NewString() + "@test.local"
	var userID uuid.UUID
	_ = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, _ := store.CreateUser(ctx, q, email, "Reset Test", nil)
		userID = u.ID
		return nil
	})
	t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) })

	p, _, _ := svc.Create(ctx, policy.CreateInput{
		UserID:           userID,
		Title:            "reset test",
		IntervalDays:     14,
		GracePeriodHours: 72,
		ReleaseMode:      "private",
		UserSignature:    make([]byte, ed25519.SignatureSize),
	})
	_ = svc.Arm(ctx, userID, p.ID)

	clk.Advance(14*24*time.Hour - 23*time.Hour)
	_ = sched.Tick(ctx)
	assertState(t, s, p.ID, "warning")

	// Create a real device (FK constraint requires one).
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var deviceID uuid.UUID
	_ = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		d, e := store.CreateDevice(ctx, q, &store.Device{
			UserID:       userID,
			Platform:     "android",
			Nickname:     "test-dev",
			DevicePubKey: devPub,
			TrustedAfter: clk.Now(),
		})
		if e == nil {
			deviceID = d.ID
		}
		return e
	})
	if err := svc.CheckIn(ctx, userID, p.ID, &deviceID); err != nil {
		t.Fatal(err)
	}
	assertState(t, s, p.ID, "healthy")

	// Deadline should be ~14 days from 'now' again.
	ps, _ := store.GetPolicyState(ctx, s.Pool, p.ID)
	want := clk.Now().Add(14 * 24 * time.Hour)
	if ps.NextDueAt == nil || ps.NextDueAt.Sub(want).Abs() > time.Minute {
		t.Fatalf("next_due_at not reset: got %v want ~%v", ps.NextDueAt, want)
	}
}

func assertState(t *testing.T, s *store.Store, id uuid.UUID, want string) {
	t.Helper()
	p, err := store.GetPolicy(context.Background(), s.Pool, id)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != want {
		t.Fatalf("state: want %s, got %s", want, p.State)
	}
}
