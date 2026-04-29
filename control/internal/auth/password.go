package auth

// Argon2id passphrase hashing.
//
// Encoded form (single string, fits a TEXT column):
//
//	argon2id$v=19$m=65536,t=3,p=2$<saltB64>$<hashB64>
//
// Parameters target ~100ms on a modern x86 server core. They can be raised
// later without breaking existing hashes — VerifyPassword reads parameters
// from the encoded string.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemoryKiB = 64 * 1024 // 64 MiB
	argonTime      = 3
	argonParallel  = 2
	argonKeyLen    = 32
	argonSaltLen   = 16

	// MinPassphraseLen is the floor we enforce server-side. Tor self-host
	// is the only auth path; weak passphrases are the dominant attack.
	MinPassphraseLen = 12
)

// ErrWeakPassphrase is returned when the passphrase fails the floor check.
var ErrWeakPassphrase = errors.New("auth: passphrase too short (min 12 chars)")

// HashPassword derives an Argon2id hash and returns the encoded form.
func HashPassword(passphrase string) (string, error) {
	if utf8.RuneCountInString(passphrase) < MinPassphraseLen {
		return "", ErrWeakPassphrase
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemoryKiB, argonParallel, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonParallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks passphrase against the encoded hash. Returns nil on
// match; an error otherwise (including malformed input).
func VerifyPassword(passphrase, encoded string) error {
	parts := strings.Split(encoded, "$")
	// "argon2id" "v=19" "m=...,t=...,p=..." "<salt>" "<hash>"
	if len(parts) != 5 || parts[0] != "argon2id" {
		return errors.New("auth: bad password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return fmt.Errorf("auth: bad version: %w", err)
	}
	if version != argon2.Version {
		return fmt.Errorf("auth: unsupported argon2 version %d", version)
	}
	var mem, t, p uint32
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return fmt.Errorf("auth: bad params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("auth: bad salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("auth: bad hash: %w", err)
	}
	got := argon2.IDKey([]byte(passphrase), salt, t, mem, uint8(p), uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("auth: passphrase mismatch")
	}
	return nil
}
