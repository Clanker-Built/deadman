package auth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPGenerateAndVerifyCurrent(t *testing.T) {
	secret, err := TOTPGenerateSecret()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if strings.Contains(secret, "=") {
		t.Fatalf("secret must be unpadded base32, got %q", secret)
	}
	code, err := totpAt(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if err := TOTPVerify(secret, code); err != nil {
		t.Fatalf("verify current: %v", err)
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	secret, _ := TOTPGenerateSecret()
	if err := TOTPVerify(secret, "000000"); err == nil {
		t.Fatal("000000 should not be accepted")
	}
	if err := TOTPVerify(secret, "12345"); err == nil {
		t.Fatal("5-digit code should be rejected")
	}
}

func TestTOTPDriftWindow(t *testing.T) {
	secret, _ := TOTPGenerateSecret()
	// Code from the previous step should still verify (±30s tolerance).
	prev, err := totpAt(secret, time.Now().UTC().Add(-31*time.Second))
	if err != nil {
		t.Fatalf("prev: %v", err)
	}
	if err := TOTPVerify(secret, prev); err != nil {
		t.Fatalf("prev step should be in drift window: %v", err)
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("ABCDEFGHIJKLMNOP", "alice@example.com", "Deadman")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("bad scheme: %s", uri)
	}
	if !strings.Contains(uri, "secret=ABCDEFGHIJKLMNOP") {
		t.Fatalf("secret missing from %s", uri)
	}
	if !strings.Contains(uri, "issuer=Deadman") {
		t.Fatalf("issuer missing from %s", uri)
	}
}
