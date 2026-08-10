package auth

// RFC 6238 TOTP, HMAC-SHA1, 30-second step, 6 digits — the Google
// Authenticator default. Implemented inline to avoid pulling another
// dependency for ~30 lines of code.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 mandates HMAC-SHA1 for authenticator-app interop; used solely as the hmac.New hash, never for collision resistance
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpStepSeconds = 30
	totpDigits      = 6
	totpSecretBytes = 20 // 160-bit; matches HMAC-SHA1 block size and what GAuth expects
)

// TOTPGenerateSecret returns a fresh 160-bit TOTP secret encoded as base32
// (no padding, the canonical wire form for otpauth:// URLs).
func TOTPGenerateSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

// TOTPProvisioningURI builds the otpauth:// URL an authenticator app reads
// (manually or from a QR code). issuer appears as the account label.
func TOTPProvisioningURI(secretBase32, accountName, issuer string) string {
	v := url.Values{}
	v.Set("secret", secretBase32)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpStepSeconds))
	label := url.PathEscape(issuer + ":" + accountName)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// totpAt computes the 6-digit code for the step that contains t.
func totpAt(secretBase32 string, t time.Time) (string, error) {
	// Authenticator apps strip padding; the stdlib decoder requires it.
	padded := secretBase32
	if pad := (8 - len(padded)%8) % 8; pad > 0 {
		padded += strings.Repeat("=", pad)
	}
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(padded))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	step := uint64(t.Unix()) / totpStepSeconds // #nosec G115 -- t is TOTPVerify's time.Now() ±1 step; Unix() is non-negative for any post-1970 clock, cannot wrap
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod), nil
}

// TOTPVerify accepts a 6-digit code if it matches the current step or one
// step on either side (±30s drift tolerance — same as Google's default).
func TOTPVerify(secretBase32, code string) error {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return errors.New("totp: code must be 6 digits")
	}
	now := time.Now().UTC()
	for _, dt := range []time.Duration{-totpStepSeconds * time.Second, 0, totpStepSeconds * time.Second} {
		want, err := totpAt(secretBase32, now.Add(dt))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return nil
		}
	}
	return errors.New("totp: invalid code")
}
