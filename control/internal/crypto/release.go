package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ReleaseRSABits is the modulus size for the server's release keypair.
// 3072 bits matches NIST SP 800-57 Part 1 Rev. 5 for ≥128-bit security.
const ReleaseRSABits = 3072

// SchemeRSAOAEPAESGCM is the browser-compatible bundle wrapping scheme.
//   - DEK: AES-256-GCM, random 12-byte nonce
//   - DEK wrap: RSA-OAEP with SHA-256 against the server release public key
//
// Used because WebCrypto's cross-browser support for RSA-OAEP + AES-GCM is
// uniform, while X25519 support remains patchy across engines.
const SchemeRSAOAEPAESGCM = "rsa-oaep-sha256.aes-gcm.v1"

// LoadOrCreateReleaseKey reads or generates the server release RSA keypair.
// File is PKCS#8 PEM, 0600 perms enforced, same UX as the audit signing key.
func LoadOrCreateReleaseKey(path string) (*rsa.PrivateKey, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		k, err := rsa.GenerateKey(rand.Reader, ReleaseRSABits)
		if err != nil {
			return nil, fmt.Errorf("release key gen: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return nil, fmt.Errorf("release key write: %w", err)
		}
		return k, nil
	case err != nil:
		return nil, fmt.Errorf("release key stat: %w", err)
	default:
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("release key %s has too-open permissions %v; want 0600", path, info.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("release key read: %w", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("release key: no PEM block")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("release key: not RSA")
		}
		return rsaKey, nil
	}
}

// EncryptBundleForRelease is the server-side equivalent of the browser flow,
// used by tests. Browsers will do this client-side with WebCrypto.
//
// Output: (ciphertext = nonce||ct||tag, wrappedKey = RSA-OAEP(DEK)).
func EncryptBundleForRelease(pub *rsa.PublicKey, plaintext, aad []byte) (ciphertext, wrappedKey []byte, err error) {
	dek, err := RandomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	wrappedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, []byte("deadman/release-wrap/v1"))
	if err != nil {
		return nil, nil, fmt.Errorf("rsa-oaep: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out, wrappedKey, nil
}

// DecryptBundleForRelease reverses EncryptBundleForRelease. Used by the
// release worker at trigger time.
func DecryptBundleForRelease(priv *rsa.PrivateKey, ciphertext, wrappedKey, aad []byte) ([]byte, error) {
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, []byte("deadman/release-wrap/v1"))
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep decrypt: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrAuthFailed
	}
	nonce := ciphertext[:gcm.NonceSize()]
	body := ciphertext[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}

// ReleasePublicKeyJWK returns the release public key as a JWK (RFC 7517) for
// the browser's WebCrypto importKey(). This is the shape WebCrypto wants.
func ReleasePublicKeyJWK(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RSA-OAEP-256",
		"use": "enc",
		"n":   base64URLBigInt(pub.N.Bytes()),
		"e":   base64URLBigInt(bigIntBytes(pub.E)),
		"ext": true,
	}
}

// bigIntBytes renders a small int as big-endian bytes with no leading zeros.
func bigIntBytes(e int) []byte {
	b := [8]byte{}
	n := 0
	for i := 7; i >= 0; i-- {
		if byte(e>>(8*i)) != 0 || n > 0 {
			b[n] = byte(e >> (8 * i))
			n++
		}
	}
	if n == 0 {
		return []byte{0}
	}
	return b[:n]
}
