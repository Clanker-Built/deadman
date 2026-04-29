package crypto

import "golang.org/x/crypto/curve25519"

// curve25519X25519Basepoint wraps curve25519.X25519 with the standard basepoint
// to derive a public key from a private scalar.
func curve25519X25519Basepoint(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
