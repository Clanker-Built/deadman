// Package crypto is the cryptographic core of the Deadman control plane.
//
// Design:
//
//   - Identity keys are Ed25519 (sign/verify). The root user identity key and
//     every device key are Ed25519.
//   - Policy-level wrapping uses X25519 (ECDH) between a policy key pair and
//     ephemeral keys, deriving an HKDF key over ChaCha20-Poly1305.
//   - Bundle payload encryption is ChaCha20-Poly1305 (misuse-resistant AEAD)
//     with fresh 256-bit data-encryption keys (DEKs).
//   - Threshold unseal uses 2-of-3 Shamir secret sharing over GF(2^8) via the
//     audited corvus-ch/shamir library.
//
// Zero-knowledge invariant: the server never sees bundle plaintext. All
// payloads are encrypted client-side; the DB stores only wrapped DEKs and
// ciphertext pointers.
//
// Scheme versions are encoded in every ciphertext and wrapped key so we can
// migrate algorithms without breaking old bundles (§14.6 crypto-agility).
package crypto
