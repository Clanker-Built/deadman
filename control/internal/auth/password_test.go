package auth

import (
	"errors"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	pw := "correct horse battery staple"
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyPassword(pw, h); err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if err := VerifyPassword("wrong", h); err == nil {
		t.Fatal("verify bad: expected error, got nil")
	}
}

func TestPasswordRejectsShort(t *testing.T) {
	_, err := HashPassword("short")
	if !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("want ErrWeakPassphrase, got %v", err)
	}
}

func TestPasswordRejectsMalformedHash(t *testing.T) {
	if err := VerifyPassword("anything", "not-a-hash"); err == nil {
		t.Fatal("expected error on malformed hash")
	}
}
