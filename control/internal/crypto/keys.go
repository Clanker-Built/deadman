package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Ed25519KeyPair is an identity (sign/verify) keypair.
type Ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateEd25519 generates a new Ed25519 keypair using crypto/rand.
func GenerateEd25519() (Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519KeyPair{}, fmt.Errorf("ed25519 generate: %w", err)
	}
	return Ed25519KeyPair{Public: pub, Private: priv}, nil
}

// Sign signs msg with the private key. Returns a 64-byte signature.
func (k Ed25519KeyPair) Sign(msg []byte) []byte {
	return ed25519.Sign(k.Private, msg)
}

// VerifyEd25519 verifies a signature. Constant-time.
func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// X25519KeyPair is a Diffie-Hellman keypair on Curve25519.
type X25519KeyPair struct {
	Public  [32]byte
	Private [32]byte
}

// GenerateX25519 generates a new X25519 keypair.
func GenerateX25519() (X25519KeyPair, error) {
	var kp X25519KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return X25519KeyPair{}, fmt.Errorf("x25519 rand: %w", err)
	}
	// Curve25519 clamping is handled by curve25519.X25519.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return X25519KeyPair{}, fmt.Errorf("x25519 pub: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// X25519SharedSecret computes an ECDH shared secret. Rejects low-order points.
func X25519SharedSecret(priv, peerPub [32]byte) ([]byte, error) {
	secret, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return nil, fmt.Errorf("x25519 shared: %w", err)
	}
	if isAllZero(secret) {
		return nil, errors.New("x25519: low-order point rejected")
	}
	return secret, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}

func isAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
