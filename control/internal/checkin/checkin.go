// Package checkin implements the signed-nonce check-in protocol (§12.5).
//
// Flow:
//
//  1. Device (authenticated via passkey session) calls POST /checkin/nonce.
//     Server generates a random 32-byte nonce, stores it with
//     (device_id, issued_at, expires_at), and returns it.
//  2. Device signs SHA256("deadman/checkin/v1" || nonce || counter) with its
//     hardware-backed Ed25519 key and POSTs to /checkin/verify with
//     (nonce, counter, signature).
//  3. Server looks up the nonce (single-use), verifies the signature with the
//     enrolled device pubkey, ensures counter > last_counter, consumes the
//     nonce, updates device, emits a checkin audit event, and resets policy
//     state (M2 integration — for now returns success without policy touch).
//
// Security properties:
//   - Replay: nonces are single-use and expire in 60s; monotonic counter
//     catches replay of an old (nonce, counter, sig) triple even within the
//     TTL window.
//   - Cross-device replay: signature is bound to a specific device by the
//     device key registered at enrollment.
//   - Cross-purpose: domain-separation prefix "deadman/checkin/v1".
//   - Revoked devices: enforced at nonce issuance.
package checkin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DomainPrefix is mixed into the signed payload to prevent cross-protocol
// reuse (e.g. using a device key to sign something other than a check-in).
const DomainPrefix = "deadman/checkin/v1"

// NonceTTL bounds the time a device has to complete a check-in.
const NonceTTL = 60 * time.Second

// NonceSize is the raw-bytes size of a check-in nonce.
const NonceSize = 32

// Issued is the server-side record of an outstanding nonce.
type Issued struct {
	Nonce     [NonceSize]byte
	DeviceID  uuid.UUID
	UserID    uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Store is a simple in-memory nonce store. Fine for single-process M1/M2;
// swap for Redis when the control plane scales horizontally (M4).
type Store struct {
	mu   sync.Mutex
	byID map[[NonceSize]byte]Issued
}

func NewStore() *Store { return &Store{byID: make(map[[NonceSize]byte]Issued)} }

// Issue creates and stores a fresh nonce.
func (s *Store) Issue(deviceID, userID uuid.UUID) (Issued, error) {
	var n [NonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		return Issued{}, err
	}
	now := time.Now().UTC()
	is := Issued{
		Nonce:     n,
		DeviceID:  deviceID,
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(NonceTTL),
	}
	s.mu.Lock()
	s.byID[n] = is
	s.gcLocked(now)
	s.mu.Unlock()
	return is, nil
}

// Consume returns the record for nonce and removes it in one atomic step.
// Returns false if the nonce is unknown, expired, or already consumed.
func (s *Store) Consume(nonce [NonceSize]byte) (Issued, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	is, ok := s.byID[nonce]
	if !ok {
		return Issued{}, false
	}
	delete(s.byID, nonce)
	if time.Now().UTC().After(is.ExpiresAt) {
		return Issued{}, false
	}
	return is, true
}

func (s *Store) gcLocked(now time.Time) {
	for k, v := range s.byID {
		if now.After(v.ExpiresAt) {
			delete(s.byID, k)
		}
	}
}

// Payload builds the canonical byte string the device signs:
// SHA256( domain || nonce || counter_big_endian ).
//
// Exposed so clients (and tests) use the same construction.
func Payload(nonce [NonceSize]byte, counter int64) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainPrefix))
	h.Write(nonce[:])
	var cbuf [8]byte
	binary.BigEndian.PutUint64(cbuf[:], uint64(counter)) // #nosec G115 -- same-width int64->uint64 reinterpretation, bijective hash-input serialization; Verify rejects counter <= lastCounter (monotonic, starts at 0) before hashing
	h.Write(cbuf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify validates a presented check-in signature against the stored nonce
// and device public key. It also enforces monotonic counter strictness.
//
// Returns the issued record on success so the caller can proceed with the
// business-level action (reset policy state, audit).
func Verify(ctx context.Context, s *Store, nonce [NonceSize]byte, counter int64, sig []byte, devicePub ed25519.PublicKey, lastCounter int64) (Issued, error) {
	_ = ctx
	if len(devicePub) != ed25519.PublicKeySize {
		return Issued{}, errors.New("checkin: invalid device public key")
	}
	if counter <= lastCounter {
		return Issued{}, fmt.Errorf("checkin: counter not strictly increasing (got %d, last %d)", counter, lastCounter)
	}
	is, ok := s.Consume(nonce)
	if !ok {
		return Issued{}, errors.New("checkin: nonce unknown or expired")
	}
	digest := Payload(nonce, counter)
	if !ed25519.Verify(devicePub, digest[:], sig) {
		return Issued{}, errors.New("checkin: signature verification failed")
	}
	return is, nil
}
