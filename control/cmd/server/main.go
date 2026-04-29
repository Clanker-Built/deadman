package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gcottrell/deadman/control/internal/admin"
	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/checkin"
	"github.com/gcottrell/deadman/control/internal/config"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/httpapi"
	"github.com/gcottrell/deadman/control/internal/keyvault"
	"github.com/gcottrell/deadman/control/internal/metrics"
	"github.com/gcottrell/deadman/control/internal/notify"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/release"
	"github.com/gcottrell/deadman/control/internal/scheduler"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
	"github.com/gcottrell/deadman/control/internal/verify"
	"github.com/gcottrell/deadman/control/internal/webui"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	metricsReg := metrics.NewRegistry()
	deps := httpapi.Deps{
		Logger: logger, DevMode: cfg.Env == "dev", Metrics: metricsReg,
		BootstrapAdminEmail: cfg.BootstrapAdminEmail,
		RPDisplayName:       cfg.RPDisplayName,
	}

	if cfg.DatabaseURL != "" {
		s, err := store.New(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("store init", "err", err)
			os.Exit(1)
		}
		defer s.Close()
		deps.Store = s

		pub, priv, err := audit.LoadOrCreateServiceKey(cfg.ServiceSigningKeyPath)
		if err != nil {
			logger.Error("service signing key", "err", err)
			os.Exit(1)
		}
		ledger := audit.NewLedger(priv)
		deps.Ledger = ledger
		deps.Nonces = checkin.NewStore()

		// Boot-time audit-chain integrity check. A break here means the
		// DB has been tampered with between restarts, or the service
		// signing key has been swapped. Refuse to start in either case;
		// clearing the chain is an explicit operator action via the
		// runbook. Set DEADMAN_SKIP_AUDIT_VERIFY=1 only as an emergency
		// override (also logged loudly).
		if os.Getenv("DEADMAN_SKIP_AUDIT_VERIFY") == "1" {
			logger.Warn("DEADMAN_SKIP_AUDIT_VERIFY=1 — boot-time audit verification SKIPPED")
		} else {
			vctx, vcancel := context.WithTimeout(ctx, 60*time.Second)
			if err := audit.Verify(vctx, s.Pool, pub); err != nil {
				vcancel()
				logger.Error("AUDIT CHAIN INTEGRITY CHECK FAILED — refusing to start. "+
					"This means the DB has been tampered with, the signing key "+
					"has been swapped, or the chain is corrupted. Investigate "+
					"before clearing. To override (DANGEROUS), restart with "+
					"DEADMAN_SKIP_AUDIT_VERIFY=1.", "err", err)
				os.Exit(1)
			}
			vcancel()
			logger.Info("audit chain verified at boot")
		}

		// Object storage (dual-cloud primary + backup).
		if cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
			primary, err := storage.New(ctx, storage.Config{
				Endpoint: cfg.S3PrimaryEndpoint, Region: cfg.S3Region,
				Bucket: cfg.S3PrimaryBucket, AccessKeyID: cfg.S3AccessKey,
				SecretAccessKey: cfg.S3SecretKey, PathStyle: cfg.S3PathStyle,
			})
			if err != nil {
				logger.Error("s3 primary", "err", err)
				os.Exit(1)
			}
			if err := primary.EnsureBucket(ctx); err != nil {
				logger.Warn("primary ensure bucket", "err", err)
			}
			var backup *storage.Client
			if cfg.S3BackupEndpoint != "" || cfg.S3BackupBucket != cfg.S3PrimaryBucket {
				backup, err = storage.New(ctx, storage.Config{
					Endpoint: cfg.S3BackupEndpoint, Region: cfg.S3Region,
					Bucket: cfg.S3BackupBucket, AccessKeyID: cfg.S3AccessKey,
					SecretAccessKey: cfg.S3SecretKey, PathStyle: cfg.S3PathStyle,
				})
				if err != nil {
					logger.Warn("s3 backup", "err", err)
				} else if err := backup.EnsureBucket(ctx); err != nil {
					logger.Warn("backup ensure bucket", "err", err)
				}
			}
			deps.Storage = &storage.DualWriter{Primary: primary, Backup: backup, Logger: logger}
		} else {
			logger.Warn("no S3 credentials; bundle uploads disabled")
		}

		// Release key. Threshold-protected keyvault is the supported path.
		// Legacy single-PEM is kept only for dev / migration windows.
		var keyProvider release.KeyProvider
		var adminVF *keyvault.VaultFile
		var adminLocker *keyvault.Locker
		if cfg.LegacySinglePrivateKey {
			rk, err := crypto.LoadOrCreateReleaseKey(cfg.ReleaseKeyPath)
			if err != nil {
				logger.Error("release key", "err", err)
				os.Exit(1)
			}
			deps.ReleasePubKey = &rk.PublicKey
			keyProvider = &release.StaticKey{K: rk}
			logger.Warn("LEGACY single release key in use — migrate to keyvault; set DEADMAN_LEGACY_SINGLE_KEY=false",
				"path", cfg.ReleaseKeyPath)
		} else {
			vf, locker, err := initOrLoadVault(ctx, logger, cfg)
			if err != nil {
				logger.Error("vault", "err", err)
				os.Exit(1)
			}
			deps.ReleasePubKey = locker.PublicKey()
			keyProvider = locker
			adminVF = vf
			adminLocker = locker
		}

		// Watchdog.
		wd := httpapi.NewWatchdog(pub, priv)
		deps.Watchdog = wd

		authSvc, err := auth.NewService(auth.Config{
			RPDisplayName:       cfg.RPDisplayName,
			RPID:                cfg.RPID,
			RPOrigins:           cfg.RPOrigins,
			BootstrapAdminEmail: cfg.BootstrapAdminEmail,
		}, s, ledger)
		if err != nil {
			logger.Error("auth init", "err", err)
			os.Exit(1)
		}
		deps.Auth = authSvc

		polSvc := policy.New(s, ledger, policy.RealClock)
		deps.Policy = polSvc

		rend, err := webui.NewRenderer()
		if err != nil {
			logger.Error("webui renderer", "err", err)
			os.Exit(1)
		}
		deps.WebUI = rend

		// SMTP: env fallback + DB-override resolver. The resolver rebuilds
		// a Sender each call (cached briefly), so admin config edits take
		// effect without a server restart. Password in DB is vault-wrapped
		// with the release pubkey; unwrap requires the vault unlocked.
		smtpCfg := notify.SMTPConfig{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort,
			Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
			From: cfg.SMTPFrom, InsecureSkipVerify: cfg.SMTPInsecureSkip,
		}
		var keyForMail notify.KeyProvider
		if adminLocker != nil {
			keyForMail = adminLocker
		}
		mailResolver := notify.NewResolver(smtpCfg,
			admin.NewMailSettingsLoader(s), keyForMail)
		if smtpCfg.Enabled() {
			logger.Info("smtp env fallback configured", "host", cfg.SMTPHost, "from", cfg.SMTPFrom)
		} else {
			logger.Info("smtp env fallback disabled; relying on DB settings (if any)")
		}

		// Admin panel.
		adminDeps := &admin.Deps{
			Logger: logger, Store: s, Auth: authSvc, Ledger: ledger,
			DevMode: cfg.Env == "dev",
		}
		adminMount := &admin.MountConfig{
			VaultFile:  adminVF,
			Locker:     adminLocker,
			Policy:     polSvc,
			Renderer:   rend,
			ServicePub:   pub,
			Storage:      deps.Storage,
			MailResolver: mailResolver,
			Metrics:      metricsReg,
			Backups:      buildBackupManager(logger, s, ledger, deps.Storage, cfg),
			StartupConfig: admin.EffectiveStartupConfig{
				SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort,
				SMTPUsername: cfg.SMTPUsername, SMTPFrom: cfg.SMTPFrom,
				SMTPInsecureSkip:  cfg.SMTPInsecureSkip,
				SMTPPasswordIsSet: cfg.SMTPPassword != "",
				PublicBaseURL:     os.Getenv("DEADMAN_PUBLIC_BASE_URL"),
			},
			SchedulerLastTick: func() *time.Time {
				if wd == nil {
					return nil
				}
				t := wd.LastTick()
				if t.IsZero() {
					return nil
				}
				return &t
			},
		}
		deps.Admin = adminDeps
		deps.AdminMount = adminMount

		// Release worker. Needs the object-storage primary client to read
		// bundle ciphertexts back, and the keyvault Locker to unseal.
		var relWorker *release.Worker
		if deps.Storage != nil {
			relWorker = release.New(release.Worker{
				Store:         s,
				Policy:        polSvc,
				Ledger:        ledger,
				ReleaseKey:    keyProvider,
				ServiceSigner: priv,
				ServicePub:    pub,
				Storage:       deps.Storage,
				Primary:       deps.Storage.Primary,
				PublicBaseURL: os.Getenv("DEADMAN_PUBLIC_BASE_URL"),
				Mail:          mailResolver.Current,
				Logger:        logger,
			})
		}

		// Bundle consistency verifier. Nil if only one cloud configured.
		var verifier *verify.Worker
		if deps.Storage != nil && deps.Storage.Backup != nil {
			verifier = verify.New(verify.Worker{
				Store: s, Primary: deps.Storage.Primary, Backup: deps.Storage.Backup,
				Ledger: ledger, Logger: logger,
			})
		}

		sched := scheduler.New(scheduler.Config{Interval: 30 * time.Second}, polSvc, s, logger)
		sched.SetOnTick(func() {
			wd.Tick()
			if relWorker != nil {
				if err := relWorker.Tick(ctx); err != nil {
					logger.Warn("release tick", "err", err)
				}
			}
			if verifier != nil {
				if err := verifier.Tick(ctx); err != nil {
					logger.Warn("verify tick", "err", err)
				}
			}
		})
		go func() {
			if err := sched.Run(ctx); err != nil {
				logger.Error("scheduler", "err", err)
			}
		}()

		logger.Info("wired",
			"rp_id", cfg.RPID,
			"origins", cfg.RPOrigins,
			"signing_key_path", cfg.ServiceSigningKeyPath,
		)
	} else {
		logger.Warn("no database configured; auth endpoints disabled")
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.NewRouterWithDeps(deps),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	useTLS := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	go func() {
		if useTLS {
			logger.Info("server listening (tls)", "addr", cfg.ListenAddr, "cert", cfg.TLSCertFile)
			if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server error", "err", err)
				stop()
			}
			return
		}
		logger.Info("server listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}
