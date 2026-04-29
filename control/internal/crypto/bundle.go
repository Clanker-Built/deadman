package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// BundleCiphertext is the on-disk representation of an encrypted payload.
// Only this struct ever touches persistent storage — never the plaintext.
type BundleCiphertext struct {
	Scheme     string `json:"scheme"`
	Ciphertext []byte `json:"ciphertext"`
	// ManifestHash is both metadata and AEAD additional-data; altering it
	// invalidates the authentication tag.
	ManifestHash [32]byte `json:"manifest_hash"`
}

// WrappedKey is an encrypted DEK (data-encryption key) bound to a policy.
//
// The wrapping scheme is an ephemeral X25519 -> HKDF -> ChaCha20-Poly1305
// construction. The recipient policy's long-term X25519 public key is the
// KEM target; the sender generates an ephemeral keypair per wrap.
type WrappedKey struct {
	Scheme          string   `json:"scheme"`
	EphemeralPublic [32]byte `json:"ephemeral_public"`
	Ciphertext      []byte   `json:"ciphertext"` // nonce || sealed DEK
}

var hkdfBundleWrapInfo = []byte("deadman/bundle-wrap/v1")

// EncryptBundle generates a fresh DEK, encrypts the plaintext, and wraps the
// DEK for the given policy public key. Returns the ciphertext and wrapped key.
//
// The manifest is hashed and bound as AAD so tampering with metadata breaks
// decryption.
func EncryptBundle(plaintext []byte, manifest []byte, policyPub [32]byte) (BundleCiphertext, WrappedKey, error) {
	manifestHash := sha256.Sum256(manifest)

	dek, err := RandomBytes(AEADKeySize)
	if err != nil {
		return BundleCiphertext{}, WrappedKey{}, err
	}

	ct, err := Encrypt(dek, plaintext, manifestHash[:])
	if err != nil {
		return BundleCiphertext{}, WrappedKey{}, err
	}

	wk, err := WrapKey(dek, policyPub, manifestHash[:])
	if err != nil {
		return BundleCiphertext{}, WrappedKey{}, err
	}

	return BundleCiphertext{
		Scheme:       SchemeChaCha20Poly1305,
		Ciphertext:   ct,
		ManifestHash: manifestHash,
	}, wk, nil
}

// DecryptBundle performs the inverse: unwraps the DEK with the policy private
// key, then AEAD-decrypts the payload.
func DecryptBundle(bc BundleCiphertext, wk WrappedKey, manifest []byte, policyPriv [32]byte) ([]byte, error) {
	expectHash := sha256.Sum256(manifest)
	if !ConstantTimeEqual(expectHash[:], bc.ManifestHash[:]) {
		return nil, errors.New("bundle: manifest hash mismatch")
	}
	if bc.Scheme != SchemeChaCha20Poly1305 {
		return nil, fmt.Errorf("bundle: unknown scheme %q", bc.Scheme)
	}
	dek, err := UnwrapKey(wk, policyPriv, expectHash[:])
	if err != nil {
		return nil, err
	}
	return Decrypt(dek, bc.Ciphertext, expectHash[:])
}

// WrapKey encrypts a DEK for a recipient X25519 public key, binding the
// ciphertext to aad.
func WrapKey(dek []byte, recipientPub [32]byte, aad []byte) (WrappedKey, error) {
	eph, err := GenerateX25519()
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := X25519SharedSecret(eph.Private, recipientPub)
	if err != nil {
		return WrappedKey{}, err
	}
	salt := append([]byte{}, eph.Public[:]...)
	salt = append(salt, recipientPub[:]...)
	kek, err := DeriveKey(shared, salt, hkdfBundleWrapInfo, AEADKeySize)
	if err != nil {
		return WrappedKey{}, err
	}
	ct, err := Encrypt(kek, dek, aad)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{
		Scheme:          SchemeX25519HKDFChaCha20,
		EphemeralPublic: eph.Public,
		Ciphertext:      ct,
	}, nil
}

// UnwrapKey reverses WrapKey.
func UnwrapKey(wk WrappedKey, recipientPriv [32]byte, aad []byte) ([]byte, error) {
	if wk.Scheme != SchemeX25519HKDFChaCha20 {
		return nil, fmt.Errorf("wrap: unknown scheme %q", wk.Scheme)
	}
	// Derive recipient public from private so we can reconstruct the salt.
	var recipientPub [32]byte
	recipientPair := X25519KeyPair{Private: recipientPriv}
	if err := recipientPair.fillPublic(); err != nil {
		return nil, err
	}
	recipientPub = recipientPair.Public

	shared, err := X25519SharedSecret(recipientPriv, wk.EphemeralPublic)
	if err != nil {
		return nil, err
	}
	salt := append([]byte{}, wk.EphemeralPublic[:]...)
	salt = append(salt, recipientPub[:]...)
	kek, err := DeriveKey(shared, salt, hkdfBundleWrapInfo, AEADKeySize)
	if err != nil {
		return nil, err
	}
	return Decrypt(kek, wk.Ciphertext, aad)
}

// fillPublic derives and sets the public key from an existing private key.
func (k *X25519KeyPair) fillPublic() error {
	pub, err := curve25519X25519Basepoint(k.Private[:])
	if err != nil {
		return err
	}
	copy(k.Public[:], pub)
	return nil
}

// MarshalBundle is a convenience that produces a compact JSON representation.
func MarshalBundle(bc BundleCiphertext) ([]byte, error) { return json.Marshal(bc) }

// MarshalWrappedKey is a convenience for storing the wrapped DEK.
func MarshalWrappedKey(wk WrappedKey) ([]byte, error) { return json.Marshal(wk) }
