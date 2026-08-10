package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// LoadOrCreateServiceKey reads an Ed25519 seed from path, or generates and
// persists one on first run. The file holds the 32-byte seed (not the 64-byte
// expanded private key) so it's portable and easy to audit.
//
// Permissions are enforced: the file must be 0600 or tighter. On creation we
// write with 0600.
func LoadOrCreateServiceKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, fmt.Errorf("service key rand: %w", err)
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, nil, fmt.Errorf("service key write: %w", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return priv.Public().(ed25519.PublicKey), priv, nil
	case err != nil:
		return nil, nil, fmt.Errorf("service key stat: %w", err)
	default:
		if info.Mode().Perm()&0o077 != 0 {
			return nil, nil, fmt.Errorf("service key %s has too-open permissions %v; want 0600", path, info.Mode().Perm())
		}
		seed, err := os.ReadFile(path) // #nosec G304 -- signing key path comes solely from operator config (DEADMAN_SERVICE_SIGNING_KEY_PATH via config.Load); 0600 perms enforced above
		if err != nil {
			return nil, nil, fmt.Errorf("service key read: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("service key: want %d-byte seed, got %d", ed25519.SeedSize, len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return priv.Public().(ed25519.PublicKey), priv, nil
	}
}
