package keyvault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndUnlockWithTwoPassphrases(t *testing.T) {
	vf, share3, err := Generate("alice-secret-phrase", "bob-other-phrase")
	if err != nil {
		t.Fatal(err)
	}
	if share3 == "" {
		t.Fatal("empty share3 recovery encoding")
	}
	l := NewLocker()
	if err := l.LoadPublicOnly(vf); err != nil {
		t.Fatal(err)
	}
	if l.Unlocked() {
		t.Fatal("locker should start locked")
	}
	if err := l.UnlockWithPassphrases(vf, "alice-secret-phrase", "bob-other-phrase"); err != nil {
		t.Fatal(err)
	}
	if !l.Unlocked() {
		t.Fatal("should be unlocked")
	}
	// Prove it's the real key by encrypt/decrypt.
	priv := l.PrivateKey()
	msg := []byte("integrity")
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round-trip mismatch")
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	vf, _, _ := Generate("pA", "pB")
	l := NewLocker()
	if err := l.UnlockWithPassphrases(vf, "pA-wrong", "pB"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if l.Unlocked() {
		t.Fatal("locker unlocked on wrong passphrase")
	}
}

func TestRecoveryPath(t *testing.T) {
	vf, share3, err := Generate("pA", "pB")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate passphrase B forgotten: recover using share 3 + passphrase A.
	l := NewLocker()
	if err := l.UnlockWithRecovery(vf, "pA", share3, 1); err != nil {
		t.Fatal(err)
	}
	if !l.Unlocked() {
		t.Fatal("recovery unlock failed")
	}
	// Also test recovery via passphrase B + share 3.
	l2 := NewLocker()
	if err := l2.UnlockWithRecovery(vf, "pB", share3, 2); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryFingerprintChecksTransciption(t *testing.T) {
	vf, share3, _ := Generate("pA", "pB")
	// Flip a character in the share3 encoding — must fail fingerprint check.
	bad := []byte(share3)
	for i := 0; i < len(bad); i++ {
		if bad[i] != '-' {
			if bad[i] == '0' {
				bad[i] = '1'
			} else {
				bad[i] = '0'
			}
			break
		}
	}
	l := NewLocker()
	if err := l.UnlockWithRecovery(vf, "pA", string(bad), 1); err == nil {
		t.Fatal("corrupted share3 accepted")
	}
}

func TestFileRoundTrip(t *testing.T) {
	vf, _, _ := Generate("pA", "pB")
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	if err := WriteFile(path, vf); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perms want 0600 got %v", info.Mode().Perm())
	}
	vf2, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocker()
	if err := l.UnlockWithPassphrases(vf2, "pA", "pB"); err != nil {
		t.Fatal(err)
	}
}

func TestLockClearsKey(t *testing.T) {
	vf, _, _ := Generate("pA", "pB")
	l := NewLocker()
	if err := l.UnlockWithPassphrases(vf, "pA", "pB"); err != nil {
		t.Fatal(err)
	}
	l.Lock()
	if l.Unlocked() {
		t.Fatal("still unlocked after Lock()")
	}
	if l.PrivateKey() != nil {
		t.Fatal("private key not cleared")
	}
}

func TestSamePassphraseRejected(t *testing.T) {
	if _, _, err := Generate("same", "same"); err == nil {
		t.Fatal("accepted identical passphrases (no trust split)")
	}
}
