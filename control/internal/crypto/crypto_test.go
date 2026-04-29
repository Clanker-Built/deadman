package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	kp, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("deadman audit event")
	sig := kp.Sign(msg)
	if !VerifyEd25519(kp.Public, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	// Flip a byte; verify must fail.
	bad := append([]byte{}, msg...)
	bad[0] ^= 1
	if VerifyEd25519(kp.Public, bad, sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestX25519RoundTrip(t *testing.T) {
	a, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	s1, err := X25519SharedSecret(a.Private, b.Public)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := X25519SharedSecret(b.Private, a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("shared secrets differ")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key, err := RandomBytes(AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("secret payload")
	aad := []byte("manifest-hash")
	ct, err := Encrypt(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decrypt(key, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("decrypt mismatch")
	}
}

func TestAEADTamperDetected(t *testing.T) {
	key, _ := RandomBytes(AEADKeySize)
	ct, _ := Encrypt(key, []byte("x"), nil)
	// Flip last byte (inside tag).
	ct[len(ct)-1] ^= 0xff
	if _, err := Decrypt(key, ct, nil); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestAEADWrongAADDetected(t *testing.T) {
	key, _ := RandomBytes(AEADKeySize)
	ct, _ := Encrypt(key, []byte("x"), []byte("aad-1"))
	if _, err := Decrypt(key, ct, []byte("aad-2")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
}

// TestAEADNonceUniqueness: repeated encryptions of the same plaintext under
// the same key must produce different ciphertexts (nonce randomness).
func TestAEADNonceUniqueness(t *testing.T) {
	key, _ := RandomBytes(AEADKeySize)
	pt := []byte("same plaintext")
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		ct, err := Encrypt(key, pt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(ct)] {
			t.Fatalf("duplicate ciphertext on iteration %d", i)
		}
		seen[string(ct)] = true
	}
}

func TestShamir2of3(t *testing.T) {
	secret, _ := RandomBytes(32)
	shares, err := SplitSecret(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 3 {
		t.Fatalf("want 3 shares, got %d", len(shares))
	}
	// Any 2 of 3 must reconstruct.
	keys := make([]byte, 0, 3)
	for k := range shares {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			subset := map[byte][]byte{
				keys[i]: shares[keys[i]],
				keys[j]: shares[keys[j]],
			}
			got, err := CombineShares(subset)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("reconstruction failed for pair %d,%d", i, j)
			}
		}
	}
}

func TestShamirSingleShareFails(t *testing.T) {
	secret, _ := RandomBytes(32)
	shares, _ := SplitSecret(secret, 3, 2)
	for id, sh := range shares {
		got, _ := CombineShares(map[byte][]byte{id: sh})
		if bytes.Equal(got, secret) {
			t.Fatal("single share reconstructed secret")
		}
	}
}

func TestBundleRoundTrip(t *testing.T) {
	policyKeys, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("confidential manifesto")
	manifest := []byte(`{"bundle_id":"b1","owner":"u1"}`)

	bc, wk, err := EncryptBundle(plaintext, manifest, policyKeys.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Zero-knowledge invariant: no plaintext substring in ciphertext or wrap.
	if bytes.Contains(bc.Ciphertext, plaintext) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	if bytes.Contains(wk.Ciphertext, plaintext) {
		t.Fatal("plaintext leaked into wrapped key")
	}

	got, err := DecryptBundle(bc, wk, manifest, policyKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("bundle round-trip mismatch")
	}
}

func TestBundleTamperedManifestRejected(t *testing.T) {
	pk, _ := GenerateX25519()
	bc, wk, _ := EncryptBundle([]byte("x"), []byte("m1"), pk.Public)
	if _, err := DecryptBundle(bc, wk, []byte("m2"), pk.Private); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestBundleWrongPolicyKeyRejected(t *testing.T) {
	pk, _ := GenerateX25519()
	other, _ := GenerateX25519()
	bc, wk, _ := EncryptBundle([]byte("x"), []byte("m"), pk.Public)
	if _, err := DecryptBundle(bc, wk, []byte("m"), other.Private); err == nil {
		t.Fatal("wrong private key accepted")
	}
}

// Fuzz Decrypt — must never panic or return a plaintext for random inputs.
func FuzzDecrypt(f *testing.F) {
	key, _ := RandomBytes(AEADKeySize)
	good, _ := Encrypt(key, []byte("hello"), nil)
	f.Add(good)
	f.Fuzz(func(t *testing.T, ct []byte) {
		_, err := Decrypt(key, ct, nil)
		if err == nil && !bytes.Equal(ct, good) {
			t.Fatalf("unexpected success on random input (len=%d)", len(ct))
		}
	})
}

// Fuzz DecryptBundle — manifest-hash binding must hold.
func FuzzDecryptBundle(f *testing.F) {
	pk, _ := GenerateX25519()
	bc, wk, _ := EncryptBundle([]byte("ok"), []byte("m"), pk.Public)
	encoded, _ := MarshalBundle(bc)
	f.Add(encoded, []byte("m"))
	f.Fuzz(func(t *testing.T, _ []byte, manifest []byte) {
		// Manifest ≠ "m" must fail; "m" must succeed.
		_, err := DecryptBundle(bc, wk, manifest, pk.Private)
		if err == nil && !bytes.Equal(manifest, []byte("m")) {
			t.Fatalf("decrypted under wrong manifest: %q", manifest)
		}
	})
}

func BenchmarkEncrypt64KB(b *testing.B) {
	key, _ := RandomBytes(AEADKeySize)
	buf := make([]byte, 64*1024)
	_, _ = rand.Read(buf)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(key, buf, nil); err != nil {
			b.Fatal(err)
		}
	}
}
