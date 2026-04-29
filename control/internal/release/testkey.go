package release

import "crypto/rsa"

// StaticKey is a KeyProvider that always returns the given key. Intended
// for tests and for single-cloud dev instances that haven't adopted the
// threshold keyvault yet. Production deployments should use keyvault.Locker.
type StaticKey struct{ K *rsa.PrivateKey }

func (s *StaticKey) PrivateKey() *rsa.PrivateKey { return s.K }
func (s *StaticKey) Unlocked() bool              { return s.K != nil }
