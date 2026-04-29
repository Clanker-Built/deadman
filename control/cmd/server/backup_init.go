package main

import (
	"log/slog"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/backups"
	"github.com/gcottrell/deadman/control/internal/config"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// buildBackupManager returns a configured backup manager, or nil if the
// prerequisites for backups aren't met (no storage, no ledger).
// Destination preference: backup bucket > primary bucket.
func buildBackupManager(logger *slog.Logger, s *store.Store, ledger *audit.Ledger,
	sw *storage.DualWriter, cfg *config.Config) *backups.Manager {
	if s == nil || ledger == nil || sw == nil {
		return nil
	}
	dest := sw.Backup
	if dest == nil {
		dest = sw.Primary
	}
	if dest == nil {
		return nil
	}
	return &backups.Manager{
		Logger:      logger,
		Store:       s,
		Ledger:      ledger,
		Destination: dest,
		DatabaseURL: cfg.DatabaseURL,
		KeepCount:   cfg.BackupKeepCount,
	}
}
