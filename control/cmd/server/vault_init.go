package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/gcottrell/deadman/control/internal/config"
	"github.com/gcottrell/deadman/control/internal/keyvault"
)

// initOrLoadVault opens the threshold vault file if it exists, or generates
// a new one on first run. If the vault exists and the operator supplied
// both passphrases via env, auto-unlocks. Otherwise returns with the Locker
// holding only the public key — releases will stall until unlocked via a
// future admin endpoint or a restart with env vars set.
//
// On fresh generation, prints the recovery share (share 3) to stderr so the
// operator can write it down and store it offline. After that the program
// continues to run normally (auto-unlocked, since the passphrases are
// already in hand).
func initOrLoadVault(_ context.Context, logger *slog.Logger, cfg *config.Config) (*keyvault.VaultFile, *keyvault.Locker, error) {
	locker := keyvault.NewLocker()

	// Existing vault path: load, then attempt unlock.
	if _, err := os.Stat(cfg.VaultPath); err == nil {
		vf, err := keyvault.ReadFile(cfg.VaultPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read vault: %w", err)
		}
		if err := locker.LoadPublicOnly(vf); err != nil {
			return nil, nil, fmt.Errorf("vault pubkey: %w", err)
		}
		if cfg.VaultPassA != "" && cfg.VaultPassB != "" {
			if err := locker.UnlockWithPassphrases(vf, cfg.VaultPassA, cfg.VaultPassB); err != nil {
				logger.Error("vault unlock failed; running locked. Fix passphrases and restart.", "err", err)
			} else {
				logger.Info("vault unlocked via env passphrases")
			}
		} else {
			logger.Warn("vault is locked (no passphrases in env). Releases will stall until unlocked.")
		}
		return vf, locker, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	// Fresh generation. Require both passphrases via env for unattended dev;
	// production operators should generate the vault interactively via a
	// separate CLI (planned). For now, block startup if passphrases missing.
	if cfg.VaultPassA == "" || cfg.VaultPassB == "" {
		return nil, nil, errors.New(
			"no vault file and no DEADMAN_VAULT_PASSPHRASE_A / _B set. " +
				"For a fresh install set both env vars; the server will generate a " +
				"new vault and print the offline recovery share (share 3) once. " +
				"Record it out-of-band, then optionally unset the passphrases for " +
				"interactive startup on subsequent boots (not yet supported — M5+)")
	}

	vf, share3, err := keyvault.Generate(cfg.VaultPassA, cfg.VaultPassB)
	if err != nil {
		return nil, nil, fmt.Errorf("vault generate: %w", err)
	}
	if err := keyvault.WriteFile(cfg.VaultPath, vf); err != nil {
		return nil, nil, fmt.Errorf("write vault: %w", err)
	}
	if err := locker.UnlockWithPassphrases(vf, cfg.VaultPassA, cfg.VaultPassB); err != nil {
		return nil, nil, fmt.Errorf("initial unlock: %w", err)
	}

	// Print share 3 loudly. This is the one-time moment the operator can
	// capture it. After this line, share 3 is not recoverable.
	fmt.Fprintln(os.Stderr, "\n================================================================")
	fmt.Fprintln(os.Stderr, "  DEADMAN THRESHOLD VAULT CREATED — RECORD THIS NOW")
	fmt.Fprintln(os.Stderr, "----------------------------------------------------------------")
	fmt.Fprintln(os.Stderr, "  Offline recovery share (share 3). Write this down,")
	fmt.Fprintln(os.Stderr, "  store it in a safe you control, and never keep it on a")
	fmt.Fprintln(os.Stderr, "  machine connected to this deployment.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  "+share3)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  You can recover from loss of EITHER passphrase using this")
	fmt.Fprintln(os.Stderr, "  share plus whichever passphrase you still remember.")
	fmt.Fprintln(os.Stderr, "  The server has already printed this ONCE. It will not be")
	fmt.Fprintln(os.Stderr, "  printed again. A fingerprint is recorded in the vault for")
	fmt.Fprintln(os.Stderr, "  verification at recovery time.")
	fmt.Fprintln(os.Stderr, "================================================================")
	logger.Info("vault generated and unlocked", "path", cfg.VaultPath)
	return vf, locker, nil
}
