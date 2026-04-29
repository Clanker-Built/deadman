package crypto

import (
	"errors"
	"fmt"

	shamir "github.com/corvus-ch/shamir"
)

// SplitSecret splits secret into n shares where threshold are required to
// reconstruct. This is the core primitive behind the 2-of-3 threshold unseal
// (user / cloud KMS / offline recovery).
//
// Shares are returned as a map from share-identifier byte to share bytes.
// The identifier is part of the share format; do not drop it.
func SplitSecret(secret []byte, n, threshold int) (map[byte][]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: empty secret")
	}
	if threshold < 2 {
		return nil, errors.New("shamir: threshold must be >= 2")
	}
	if n < threshold {
		return nil, errors.New("shamir: n < threshold")
	}
	shares, err := shamir.Split(secret, n, threshold)
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}
	return shares, nil
}

// CombineShares reconstructs a secret from any threshold shares.
func CombineShares(shares map[byte][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("shamir: no shares provided")
	}
	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w", err)
	}
	return secret, nil
}
