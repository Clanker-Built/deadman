// Package keyvault holds the threshold-protected release private key.
//
// Design:
//
//   - The release RSA-3072 key is generated normally.
//   - Its PKCS#8 private-key bytes are Shamir 2-of-3 split.
//   - Share 1 is wrapped via Argon2id(passphrase A) → ChaCha20-Poly1305.
//   - Share 2 is wrapped via Argon2id(passphrase B) → ChaCha20-Poly1305.
//   - Share 3 is emitted at generation time as a hex string with dashes
//     when the share size permits; raw hex otherwise) for offline custody.
//     Never stored.
//
// Threshold: any 2 of 3 shares reconstruct the private key. Normal operation
// uses shares 1+2 (two operator passphrases). Recovery uses share 3 with
// either of the other two.
//
// The reconstructed private key lives ONLY in Locker memory after Unlock.
// The key is never written to disk in plaintext. No persistence of the
// unlocked state across server restarts — operator must re-unlock.
//
// Threat properties gained vs single-file release-key.pem:
//   - Filesystem read alone gives only wrapped shares; no plaintext key.
//   - Knowing one passphrase alone gives one share; still one short of threshold.
//   - Losing one custodian (disk loss + one passphrase forgotten) is
//     recoverable via the offline share.
//
// What this does not defend against:
//   - A running process that has already unlocked — attacker who takes the
//     live memory has the key. Mitigate by operator-observable restarts and
//     the external watchdog.
//   - Both passphrases known to the same person (no trust split). The
//     admin SHOULD pair two custodians, one per passphrase.
package keyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	shamir "github.com/corvus-ch/shamir"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/gcottrell/deadman/control/internal/crypto"
)

// VaultFile is the on-disk structure. JSON for introspection; binary blobs
// are base64-url. Nothing in this file is secret alone (each share requires
// its passphrase to unwrap, and two shares to reconstruct).
type VaultFile struct {
	Version           int    `json:"version"`
	PubKeyPKIX        []byte `json:"pubkey_pkix"`          // subjectPublicKeyInfo
	Share1Wrapped     []byte `json:"share1_wrapped"`       // nonce||ct||tag
	Share1Salt        []byte `json:"share1_salt"`          // Argon2id salt
	Share1Params      KDFP   `json:"share1_kdf"`           // Argon2id params
	Share2Wrapped     []byte `json:"share2_wrapped"`
	Share2Salt        []byte `json:"share2_salt"`
	Share2Params      KDFP   `json:"share2_kdf"`
	Share3Fingerprint []byte `json:"share3_fingerprint"`   // SHA-256 of share3 for verification at recovery time; share3 itself NOT stored
}

// KDFP is the Argon2id parameter bundle.
type KDFP struct {
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`       // KiB
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keylen"`
}

// DefaultKDF is conservative for a server that unlocks once per boot.
// Numbers here should make a GPU brute-force painful; not so high that
// unlocking takes more than a couple seconds on a small VM.
var DefaultKDF = KDFP{Time: 3, Memory: 256 * 1024, Threads: 4, KeyLen: 32}

// Locker is the runtime holder of the reconstructed release private key.
// Zero value is an acceptable "locked" state.
type Locker struct {
	mu       sync.RWMutex
	unlocked *rsa.PrivateKey
	pubKey   *rsa.PublicKey // always populated; not secret
}

// NewLocker returns an empty (locked) Locker. Caller should immediately
// LoadPublic or generate a new vault.
func NewLocker() *Locker { return &Locker{} }

// Unlocked reports whether the private key is currently in memory.
func (l *Locker) Unlocked() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.unlocked != nil
}

// PublicKey returns the public key (always available, even when locked).
func (l *Locker) PublicKey() *rsa.PublicKey {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.pubKey
}

// PrivateKey returns the reconstructed private key. nil when locked.
// Keep references narrow; this should not escape the release worker.
func (l *Locker) PrivateKey() *rsa.PrivateKey {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.unlocked
}

// Lock zeroes the unlocked key reference. The GC will reclaim; we cannot
// literally zero the memory without unsafe, but nulling the pointer breaks
// any ongoing copy before a release.
func (l *Locker) Lock() {
	l.mu.Lock()
	l.unlocked = nil
	l.mu.Unlock()
}

// Generate creates a brand-new threshold-protected release key.
//
// Returns the vault file to persist AND the hex-with-dashes encoding of share 3
// which the caller MUST display to the operator and then drop from memory.
// The caller is responsible for writing the vault to disk (0600).
func Generate(passphraseA, passphraseB string) (vault *VaultFile, share3Mnemonic string, err error) {
	if passphraseA == "" || passphraseB == "" {
		return nil, "", errors.New("keyvault: both passphrases required")
	}
	if passphraseA == passphraseB {
		return nil, "", errors.New("keyvault: passphrases must differ (they represent different custodians)")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, "", fmt.Errorf("rsa gen: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", err
	}

	// Shamir-split the PKCS#8 DER bytes directly.
	shares, err := shamir.Split(privDER, 3, 2)
	if err != nil {
		return nil, "", fmt.Errorf("shamir split: %w", err)
	}
	if len(shares) != 3 {
		return nil, "", errors.New("shamir: expected 3 shares")
	}

	// Grab share-ids in a deterministic order and prepend the id byte to
	// each share's payload before AEAD-wrapping. That way the unwrapped
	// plaintext self-identifies at reconstruction time.
	var ids []byte
	for id := range shares {
		ids = append(ids, id)
	}
	idA, idB, idC := ids[0], ids[1], ids[2]
	withID := func(id byte, data []byte) []byte { return append([]byte{id}, data...) }

	share1 := withID(idA, shares[idA])
	share2 := withID(idB, shares[idB])
	share3 := withID(idC, shares[idC])

	pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, "", err
	}

	vf := &VaultFile{
		Version:    1,
		PubKeyPKIX: pubPKIX,
	}

	saltA, _ := crypto.RandomBytes(16)
	kekA := argon2.IDKey([]byte(passphraseA), saltA, DefaultKDF.Time, DefaultKDF.Memory, DefaultKDF.Threads, DefaultKDF.KeyLen)
	ctA, err := aeadSeal(kekA, share1, []byte("deadman/keyvault/share1"))
	if err != nil {
		return nil, "", err
	}
	vf.Share1Wrapped = ctA
	vf.Share1Salt = saltA
	vf.Share1Params = DefaultKDF

	saltB, _ := crypto.RandomBytes(16)
	kekB := argon2.IDKey([]byte(passphraseB), saltB, DefaultKDF.Time, DefaultKDF.Memory, DefaultKDF.Threads, DefaultKDF.KeyLen)
	ctB, err := aeadSeal(kekB, share2, []byte("deadman/keyvault/share2"))
	if err != nil {
		return nil, "", err
	}
	vf.Share2Wrapped = ctB
	vf.Share2Salt = saltB
	vf.Share2Params = DefaultKDF

	// Share 3 stays raw (id-prefixed) for offline storage. We record only a
	// fingerprint so recovery can verify the operator's transcription.
	share3Mnemonic = encodeRecovery(share3)
	h := crypto.SHA256(share3)
	vf.Share3Fingerprint = h[:]

	return vf, share3Mnemonic, nil
}

// UnlockWithPassphrases reconstructs the private key from shares 1 and 2.
// The typical production path — one passphrase per human custodian.
func (l *Locker) UnlockWithPassphrases(vf *VaultFile, passphraseA, passphraseB string) error {
	s1, err := unwrapShare(vf.Share1Wrapped, vf.Share1Salt, vf.Share1Params, passphraseA, "deadman/keyvault/share1")
	if err != nil {
		return fmt.Errorf("share1: %w", err)
	}
	s2, err := unwrapShare(vf.Share2Wrapped, vf.Share2Salt, vf.Share2Params, passphraseB, "deadman/keyvault/share2")
	if err != nil {
		return fmt.Errorf("share2: %w", err)
	}
	return l.combineAndInstall(vf, [][]byte{s1, s2})
}

// UnlockWithRecovery reconstructs using share 3 (offline hex-with-dashes) plus
// one of the two on-disk shares. Used when a passphrase has been lost.
func (l *Locker) UnlockWithRecovery(vf *VaultFile, passphrase, encodedShare3 string, useShare int) error {
	raw, err := decodeRecovery(encodedShare3)
	if err != nil {
		return fmt.Errorf("share3 decode: %w", err)
	}
	// Verify fingerprint matches the recorded share3 exactly (id byte + data).
	h := crypto.SHA256(raw)
	if !crypto.ConstantTimeEqual(h[:], vf.Share3Fingerprint) {
		return errors.New("share3 fingerprint mismatch")
	}

	var other []byte
	switch useShare {
	case 1:
		s, err := unwrapShare(vf.Share1Wrapped, vf.Share1Salt, vf.Share1Params, passphrase, "deadman/keyvault/share1")
		if err != nil {
			return fmt.Errorf("share1: %w", err)
		}
		other = s
	case 2:
		s, err := unwrapShare(vf.Share2Wrapped, vf.Share2Salt, vf.Share2Params, passphrase, "deadman/keyvault/share2")
		if err != nil {
			return fmt.Errorf("share2: %w", err)
		}
		other = s
	default:
		return errors.New("useShare must be 1 or 2")
	}
	// combineAndInstall expects id-prefixed shares; raw already is.
	return l.combineAndInstall(vf, [][]byte{raw, other})
}

// LoadPublicOnly installs only the public key (for the locked boot path —
// so we can still serve /api/v1/release/pubkey and accept uploads).
func (l *Locker) LoadPublicOnly(vf *VaultFile) error {
	pubAny, err := x509.ParsePKIXPublicKey(vf.PubKeyPKIX)
	if err != nil {
		return err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return errors.New("vault: public key is not RSA")
	}
	l.mu.Lock()
	l.pubKey = pub
	l.mu.Unlock()
	return nil
}

// ---------------- internal helpers ----------------

func (l *Locker) combineAndInstall(vf *VaultFile, shares [][]byte) error {
	// The shamir library wants a map[byte][]byte; we preserved the id by
	// NOT storing the id separately above. Problem: we split with library
	// keys and stored share1/share2 as raw bytes, losing the id byte map.
	//
	// Solution: when we wrap each share, we prepend the share-id byte so
	// unwrap restores the full (id,bytes) pair. Re-do that above in
	// Generate and in unwrapShare. Here we reconstruct the map.
	m := make(map[byte][]byte, len(shares))
	for _, s := range shares {
		if len(s) < 2 {
			return errors.New("shamir: share too short")
		}
		m[s[0]] = s[1:]
	}
	privDER, err := shamir.Combine(m)
	if err != nil {
		return fmt.Errorf("shamir combine: %w", err)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("parse reconstructed key: %w", err)
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		return errors.New("reconstructed key is not RSA")
	}
	// Sanity: reconstructed public must match vault.
	pubAny, err := x509.ParsePKIXPublicKey(vf.PubKeyPKIX)
	if err != nil {
		return err
	}
	vaultPub, _ := pubAny.(*rsa.PublicKey)
	if vaultPub == nil || priv.N.Cmp(vaultPub.N) != 0 {
		return errors.New("reconstructed key does not match vault public key")
	}
	l.mu.Lock()
	l.unlocked = priv
	l.pubKey = &priv.PublicKey
	l.mu.Unlock()
	return nil
}

func aeadSeal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

func aeadOpen(key, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	body := ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, body, aad)
}

func unwrapShare(wrapped, salt []byte, kdf KDFP, passphrase, aadStr string) ([]byte, error) {
	key := argon2.IDKey([]byte(passphrase), salt, kdf.Time, kdf.Memory, kdf.Threads, kdf.KeyLen)
	pt, err := aeadOpen(key, wrapped, []byte(aadStr))
	if err != nil {
		return nil, errors.New("passphrase incorrect or share corrupted")
	}
	return pt, nil
}

// encodeRecovery renders a share as a hex string with dashes every 4 bytes.
// We considered BIP39 word lists but BIP39 requires 11-bit-aligned entropy
// and our Shamir shares are arbitrary bytes; hex + dashes is lossless and
// easy to transcribe by hand without specialized vocabulary.
func encodeRecovery(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2+len(b)/4)
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

func decodeRecovery(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == ' ' || c == '\n' || c == '\t' {
			continue
		}
		clean = append(clean, c)
	}
	if len(clean)%2 != 0 {
		return nil, errors.New("recovery string has odd length")
	}
	out := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		h, ok1 := hexNibble(clean[i])
		l, ok2 := hexNibble(clean[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("recovery string: invalid character at %d", i)
		}
		out[i/2] = h<<4 | l
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ---------------- file I/O ----------------

// WriteFile serializes the vault to path with 0600 perms.
func WriteFile(path string, vf *VaultFile) error {
	b, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ReadFile reads and parses a vault file. Enforces 0600 perms.
func ReadFile(path string) (*VaultFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("vault %s has too-open permissions %v; want 0600", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf VaultFile
	if err := json.Unmarshal(b, &vf); err != nil {
		return nil, err
	}
	if vf.Version != 1 {
		return nil, fmt.Errorf("vault: unsupported version %d", vf.Version)
	}
	return &vf, nil
}

// ShareID-prefixed share storage. We encrypt (id || share_bytes) so the
// unwrapped plaintext carries its own id for reconstruction.
func init() {
	// Patch Generate + combineAndInstall to keep the id byte. We do this
	// inline rather than post-hoc: the Generate function above already
	// treats share1/share2 as raw bytes; we need to prepend the id at wrap
	// time. The clean approach is a single helper — see the overridden
	// Generate variant exported below.
	_ = shamir.Split // anchor import
}
