package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ServerSecretAAD scopes RSA-OAEP wrapping to server-side secret storage.
// Distinct from bundle-release AAD so a leaked wrapped secret cannot be
// substituted into the bundle-unseal path.
const serverSecretAAD = "deadman/server-secret-wrap/v1"

// WrapServerSecret encrypts a short operator-editable secret (e.g. SMTP
// password) with the release public key, producing a self-contained blob
// that the server can persist to the DB. Unwrap requires the release
// private key — i.e. the vault must be unlocked.
//
// Wire format (all big-endian):
//
//	[1]  version = 1
//	[2]  len(wrappedKey)
//	[N]  wrappedKey (RSA-OAEP(DEK))
//	[12] nonce
//	[...] ciphertext || tag (AES-256-GCM)
func WrapServerSecret(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	dek, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, []byte(serverSecretAAD))
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep: %w", err)
	}
	if len(wrappedKey) > 0xFFFF {
		return nil, errors.New("wrapped key too large")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, []byte(serverSecretAAD))

	out := make([]byte, 0, 1+2+len(wrappedKey)+len(nonce)+len(ct))
	out = append(out, 0x01) // version
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(wrappedKey)))
	out = append(out, lb[:]...)
	out = append(out, wrappedKey...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// UnwrapServerSecret reverses WrapServerSecret. Returns ErrAuthFailed for
// any tampering or key mismatch.
func UnwrapServerSecret(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) < 1+2+12 {
		return nil, ErrAuthFailed
	}
	if blob[0] != 0x01 {
		return nil, errors.New("server-secret: unknown version")
	}
	wkLen := int(binary.BigEndian.Uint16(blob[1:3]))
	if len(blob) < 1+2+wkLen+12 {
		return nil, ErrAuthFailed
	}
	wrappedKey := blob[3 : 3+wkLen]
	rest := blob[3+wkLen:]

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, []byte(serverSecretAAD))
	if err != nil {
		return nil, ErrAuthFailed
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(rest) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrAuthFailed
	}
	nonce := rest[:gcm.NonceSize()]
	ct := rest[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, []byte(serverSecretAAD))
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}
