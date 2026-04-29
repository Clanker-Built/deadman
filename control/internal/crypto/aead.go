package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Scheme identifiers. Persisted alongside ciphertexts so the decrypter can
// dispatch to the correct primitive. Never reuse an identifier.
const (
	// SchemeChaCha20Poly1305 — ChaCha20-Poly1305 AEAD with 12-byte random nonce.
	SchemeChaCha20Poly1305 = "chacha20poly1305.v1"

	// SchemeX25519HKDFChaCha20 — sender-key wrap: ephemeral X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305.
	SchemeX25519HKDFChaCha20 = "x25519-hkdf-sha256-chacha20poly1305.v1"
)

// base64URLBigInt encodes bytes as unpadded base64url. Defined here to avoid
// a circular import from the release JWK code.
func base64URLBigInt(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(b) == 0 {
		return ""
	}
	// Handle length in groups of 3 bytes -> 4 chars.
	var out []byte
	i := 0
	for ; i+3 <= len(b); i += 3 {
		v := uint(b[i])<<16 | uint(b[i+1])<<8 | uint(b[i+2])
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f], alphabet[(v>>6)&0x3f], alphabet[v&0x3f])
	}
	switch len(b) - i {
	case 1:
		v := uint(b[i]) << 16
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f])
	case 2:
		v := uint(b[i])<<16 | uint(b[i+1])<<8
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f], alphabet[(v>>6)&0x3f])
	}
	return string(out)
}

// AEADKeySize is the required key size for the default AEAD.
const AEADKeySize = chacha20poly1305.KeySize

// ErrAuthFailed is returned when authenticated decryption fails.
var ErrAuthFailed = errors.New("crypto: authentication failed")

// Encrypt encrypts plaintext with ChaCha20-Poly1305.
//
// The output format is: nonce (12 bytes) || ciphertext || tag. The nonce is
// random; do not reuse a key/nonce pair across messages. This function draws
// a fresh nonce per call from crypto/rand.
//
// aad is additional authenticated data; it is not encrypted but is bound to
// the ciphertext. Pass the bundle manifest hash or similar context here so
// that mix-and-match attacks are detected on decrypt.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("aead: key must be %d bytes, got %d", AEADKeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	nonce, err := RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Decrypt reverses Encrypt. Returns ErrAuthFailed on any authentication failure.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("aead: key must be %d bytes, got %d", AEADKeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrAuthFailed
	}
	nonce := ciphertext[:aead.NonceSize()]
	body := ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}

// DeriveKey stretches a shared secret into an AEAD key via HKDF-SHA256.
// info should encode the key's purpose ("deadman/bundle-wrap/v1", etc.).
// salt may be empty.
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("hkdf: length must be positive")
	}
	r := hkdf.New(sha256New, secret, salt, info)
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// ConstantTimeEqual is a convenience wrapper.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
