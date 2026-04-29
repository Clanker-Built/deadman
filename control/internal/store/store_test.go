package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// requireDB returns a Store connected to DEADMAN_TEST_DATABASE_URL, or skips.
func requireDB(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DEADMAN_DATABASE_URL")
	}
	if url == "" {
		t.Skip("no DEADMAN_TEST_DATABASE_URL / DEADMAN_DATABASE_URL set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestUserCRUD(t *testing.T) {
	s := requireDB(t)
	ctx := context.Background()
	email := "crud-" + uuid.NewString() + "@test.local"
	u, err := CreateUser(ctx, s.Pool, email, "Test User", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID)
	}()

	got, err := GetUserByEmail(ctx, s.Pool, email)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID {
		t.Fatal("id mismatch")
	}

	if _, err := GetUserByEmail(ctx, s.Pool, "nobody-"+uuid.NewString()+"@test.local"); !IsNotFound(err) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
