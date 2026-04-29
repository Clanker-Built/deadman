package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

// TestBrowserCompatPath replicates exactly what the browser does in
// bundle.js: AES-GCM encrypt payload with a random DEK, wrap the DEK under
// RSA-OAEP with label "deadman/release-wrap/v1", and verify the server can
// decrypt it with the release private key. If browsers or Go change their
// RSA-OAEP label handling this test will surface it.
func TestBrowserCompatPath(t *testing.T) {
	dir := t.TempDir()
	k, err := LoadOrCreateReleaseKey(filepath.Join(dir, "rel.pem"))
	if err != nil {
		t.Fatal(err)
	}

	// Browser path.
	plaintext := []byte("browser-originating bundle payload")
	manifest := []byte(`{"label":"test","file_count":1}`)
	manifestHash := sha256.Sum256(manifest)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	out := append([]byte{}, nonce...)
	out = gcm.Seal(out, nonce, plaintext, manifestHash[:])

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.PublicKey, dek, []byte("deadman/release-wrap/v1"))
	if err != nil {
		t.Fatal(err)
	}

	// Server release worker path.
	got, err := DecryptBundleForRelease(k, out, wrapped, manifestHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("browser-compat round-trip mismatch")
	}
}
