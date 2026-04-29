package auth

import (
	"strings"
	"testing"
)

func TestRecoveryCodesRoundTrip(t *testing.T) {
	plain, hashed, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(plain) != 10 || len(hashed) != 10 {
		t.Fatalf("expected 10 codes, got %d/%d", len(plain), len(hashed))
	}
	for _, c := range plain {
		if !strings.Contains(c, "-") {
			t.Fatalf("code missing dashes: %s", c)
		}
		if len(c) != 19 { // 4-4-4-4 with three dashes = 16+3
			t.Fatalf("code length wrong: %s (%d)", c, len(c))
		}
	}

	// Consume one valid code; remaining list should drop to 9.
	rem, err := ConsumeRecoveryCode(plain[3], hashed)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(rem) != 9 {
		t.Fatalf("after consume want 9, got %d", len(rem))
	}
	// Same code can't be consumed twice.
	if _, err := ConsumeRecoveryCode(plain[3], rem); err == nil {
		t.Fatal("expected reuse to fail")
	}
}

func TestRecoveryCaseInsensitive(t *testing.T) {
	plain, hashed, _ := GenerateRecoveryCodes()
	mixed := strings.ToLower(plain[0])
	if _, err := ConsumeRecoveryCode(mixed, hashed); err != nil {
		t.Fatalf("lowercase should work: %v", err)
	}
}

func TestRecoveryRejectsGarbage(t *testing.T) {
	_, hashed, _ := GenerateRecoveryCodes()
	if _, err := ConsumeRecoveryCode("not-a-real-code", hashed); err == nil {
		t.Fatal("garbage should not match")
	}
}
