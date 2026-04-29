package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.pem")
	k1, err := LoadOrCreateReleaseKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateReleaseKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.N.Cmp(k2.N) != 0 {
		t.Fatal("reloaded key differs")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perms want 0600, got %v", st.Mode().Perm())
	}
}

func TestReleaseEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	k, err := LoadOrCreateReleaseKey(filepath.Join(dir, "rel.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("whistle-blower payload")
	aad := []byte("manifest-hash")
	ct, wk, err := EncryptBundleForRelease(&k.PublicKey, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("plaintext leaked")
	}
	got, err := DecryptBundleForRelease(k, ct, wk, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("mismatch")
	}
}

func TestReleaseAADTamperDetected(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadOrCreateReleaseKey(filepath.Join(dir, "rel.pem"))
	ct, wk, _ := EncryptBundleForRelease(&k.PublicKey, []byte("x"), []byte("aad1"))
	if _, err := DecryptBundleForRelease(k, ct, wk, []byte("aad2")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
}

func TestReleaseWrappedKeyTamperDetected(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadOrCreateReleaseKey(filepath.Join(dir, "rel.pem"))
	ct, wk, _ := EncryptBundleForRelease(&k.PublicKey, []byte("x"), nil)
	wk[0] ^= 0xff
	if _, err := DecryptBundleForRelease(k, ct, wk, nil); err == nil {
		t.Fatal("tampered wrapped key accepted")
	}
}

func TestReleaseJWK(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadOrCreateReleaseKey(filepath.Join(dir, "rel.pem"))
	jwk := ReleasePublicKeyJWK(&k.PublicKey)
	if jwk["kty"] != "RSA" || jwk["alg"] != "RSA-OAEP-256" {
		t.Fatalf("unexpected JWK: %v", jwk)
	}
	if _, ok := jwk["n"].(string); !ok {
		t.Fatal("n missing")
	}
	if _, ok := jwk["e"].(string); !ok {
		t.Fatal("e missing")
	}
}
