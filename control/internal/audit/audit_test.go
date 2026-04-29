package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/store"
)

func requireDB(t *testing.T) *store.Store {
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

func TestLedgerAppendAndVerify(t *testing.T) {
	s := requireDB(t)
	ctx := context.Background()

	// Clean the table so chain verification starts from a known state.
	// Uses the same privileged connection as the migrations role.
	// We DELETE via SQL inside a DO block to bypass the trigger only for
	// tests. In prod the trigger forbids deletes.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `TRUNCATE audit_events RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete`); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLedger(priv)

	for i := 0; i < 5; i++ {
		uid := uuid.New()
		_, err := l.Append(ctx, s, Event{
			ActorKind: ActorUser,
			ActorID:   &uid,
			EventType: "test.event",
			Payload:   map[string]any{"i": i},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	if err := Verify(ctx, s.Pool, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLedgerAppendOnlyEnforced(t *testing.T) {
	s := requireDB(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := NewLedger(priv)

	rec, err := l.Append(ctx, s, Event{
		ActorKind: ActorService,
		EventType: "test.immutability",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to mutate; the DB trigger must reject.
	_, err = s.Pool.Exec(ctx, `UPDATE audit_events SET event_type = 'tampered' WHERE id = $1`, rec.ID)
	if err == nil {
		t.Fatal("UPDATE on audit_events was allowed; trigger missing")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected error (want append-only): %v", err)
	}

	_, err = s.Pool.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, rec.ID)
	if err == nil {
		t.Fatal("DELETE on audit_events was allowed; trigger missing")
	}
}

func TestLedgerDetectsSignatureForgery(t *testing.T) {
	s := requireDB(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := NewLedger(priv)

	// Clean table.
	_, _ = s.Pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete`)
	_, _ = s.Pool.Exec(ctx, `TRUNCATE audit_events RESTART IDENTITY`)
	_, _ = s.Pool.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete`)

	_, err := l.Append(ctx, s, Event{ActorKind: ActorSystem, EventType: "t"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify against the wrong public key — must reject.
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(ctx, s.Pool, wrongPub); err == nil {
		t.Fatal("verify accepted wrong public key")
	}
}
