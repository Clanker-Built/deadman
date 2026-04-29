package crypto

import (
	"crypto/sha256"
	"hash"
)

// sha256New is a package-level hash constructor (used by HKDF).
func sha256New() hash.Hash { return sha256.New() }

// SHA256 returns the SHA-256 digest of b.
func SHA256(b []byte) [32]byte {
	return sha256.Sum256(b)
}
