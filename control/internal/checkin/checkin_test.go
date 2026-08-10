package checkin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckinHappyPath(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, err := s.Issue(uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	digest := Payload(is.Nonce, 1)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, pub, 0); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCheckinReplayRejected(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	digest := Payload(is.Nonce, 1)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, pub, 0); err != nil {
		t.Fatal(err)
	}
	// Same nonce again — must be rejected.
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 2, sig, pub, 1); err == nil {
		t.Fatal("replayed nonce accepted")
	}
}

func TestCheckinCounterMustIncrease(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	digest := Payload(is.Nonce, 5)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 5, sig, pub, 5); err == nil {
		t.Fatal("equal counter accepted")
	}
}

func TestCheckinWrongKeyRejected(t *testing.T) {
	s := NewStore()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	digest := Payload(is.Nonce, 1)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, otherPub, 0); err == nil {
		t.Fatal("signature by wrong key accepted")
	}
}

func TestCheckinExpiry(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	// Manually expire by rewriting the stored record.
	s.mu.Lock()
	entry := s.byID[is.Nonce]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	s.byID[is.Nonce] = entry
	s.mu.Unlock()
	digest := Payload(is.Nonce, 1)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, pub, 0); err == nil {
		t.Fatal("expired nonce accepted")
	}
}

// Domain separation: a signature over a payload *without* the prefix must not
// verify when the server expects the prefix.
func TestCheckinDomainSeparation(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	// Sign the raw nonce without the domain prefix — simulating a device key
	// being coerced to sign something else.
	sig := ed25519.Sign(priv, is.Nonce[:])
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, pub, 0); err == nil {
		t.Fatal("domain-separation broken: non-checkin signature accepted")
	}
}

// Cross-device binding: a nonce issued to one (device, user) must not verify
// when presented by another identity, even with a valid signature.
func TestCheckinCrossDeviceNonceRejected(t *testing.T) {
	s := NewStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is, _ := s.Issue(uuid.New(), uuid.New())
	digest := Payload(is.Nonce, 1)
	sig := ed25519.Sign(priv, digest[:])
	if _, err := Verify(context.Background(), s, is.Nonce, uuid.New(), uuid.New(), 1, sig, pub, 0); err == nil {
		t.Fatal("nonce issued to another device accepted")
	}
	// The mismatched presentation must have burned the nonce (single-use).
	if _, err := Verify(context.Background(), s, is.Nonce, is.DeviceID, is.UserID, 1, sig, pub, 0); err == nil {
		t.Fatal("burned nonce accepted by original device")
	}
}
