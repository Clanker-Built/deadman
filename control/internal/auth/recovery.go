package auth

// Recovery codes: 10 single-use codes shown once at TOTP enrollment. Stored
// as Argon2id hashes (same parameters as passphrases — small enough that
// the per-login cost is negligible since we only hash on lookup).
//
// Format: 4 groups of 4 base32 characters separated by hyphens, e.g.
// "K7QF-AJ3P-X2NM-9HRT". 80 bits of entropy per code; 10 codes share an
// exponentially small collision probability with the user's passphrase
// space.

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

const (
	recoveryCodeCount  = 10
	recoveryGroupBytes = 5 // 5 bytes -> 8 base32 chars; we slice into 4-char groups
)

// GenerateRecoveryCodes returns 10 fresh codes (plaintext, formatted) plus
// the Argon2id-hashed forms for storage. Caller persists hashes only.
func GenerateRecoveryCodes() (plaintext []string, hashed []string, err error) {
	plaintext = make([]string, recoveryCodeCount)
	hashed = make([]string, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, 10) // 80 bits
		if _, err = rand.Read(raw); err != nil {
			return nil, nil, err
		}
		// 10 bytes -> 16 base32 chars; format as 4-4-4-4.
		enc := strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
		// enc is always 16 chars for 10 input bytes.
		code := enc[0:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16]
		plaintext[i] = code
		h, err := HashPassword(strings.ReplaceAll(code, "-", "") + "____rcv") // pad to satisfy MinPassphraseLen; the suffix is constant and stripped on verify
		if err != nil {
			return nil, nil, err
		}
		hashed[i] = h
	}
	return plaintext, hashed, nil
}

// ConsumeRecoveryCode looks up a plaintext code against the user's stored
// hash list; on match, returns the new list with that hash removed. Caller
// is responsible for persisting the new list. Returns ErrUnauthorized on
// no match.
func ConsumeRecoveryCode(plaintext string, stored []string) ([]string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(plaintext), "-", ""))
	if len(normalized) != 16 {
		return nil, errors.New("auth: recovery code wrong length")
	}
	probe := normalized + "____rcv"
	for i, h := range stored {
		if err := VerifyPassword(probe, h); err == nil {
			out := make([]string, 0, len(stored)-1)
			out = append(out, stored[:i]...)
			out = append(out, stored[i+1:]...)
			return out, nil
		}
	}
	return nil, ErrUnauthorized
}
