package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr            string
	DatabaseURL           string
	Env                   string
	ServiceSigningKeyPath string
	RPDisplayName         string
	RPID                  string
	RPOrigins             []string

	S3PrimaryEndpoint string
	S3PrimaryBucket   string
	S3BackupEndpoint  string
	S3BackupBucket    string
	S3Region          string
	S3AccessKey       string
	S3SecretKey       string
	S3PathStyle       bool

	TLSCertFile string
	TLSKeyFile  string

	ReleaseKeyPath string
	VaultPath      string
	VaultPassA     string
	VaultPassB     string
	// LegacySinglePrivateKey: set to true to use the old release-key.pem
	// path instead of the threshold vault. Dev/migration only.
	LegacySinglePrivateKey bool

	SMTPHost         string
	SMTPPort         int
	SMTPUsername     string
	SMTPPassword     string
	SMTPFrom         string
	SMTPInsecureSkip bool

	// BootstrapAdminEmail: the first user to log in with this email is
	// auto-promoted to admin (once, idempotent). Ignored after any admin
	// exists. Intended for first-deploy only.
	BootstrapAdminEmail string

	// BackupKeepCount: retain this many successful admin-triggered pg_dump
	// backups before GC'ing older ones. <=0 disables retention.
	BackupKeepCount int
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:            getenv("DEADMAN_LISTEN_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("DEADMAN_DATABASE_URL"),
		Env:                   getenv("DEADMAN_ENV", "dev"),
		ServiceSigningKeyPath: getenv("DEADMAN_SERVICE_SIGNING_KEY_PATH", "./service-signing-key.bin"),
		RPDisplayName:         getenv("DEADMAN_RP_DISPLAY_NAME", "Deadman"),
		RPID:                  getenv("DEADMAN_RP_ID", "localhost"),
		RPOrigins:             splitCSV(getenv("DEADMAN_RP_ORIGINS", "http://localhost:8080")),

		S3PrimaryEndpoint: os.Getenv("DEADMAN_S3_PRIMARY_ENDPOINT"),
		S3PrimaryBucket:   getenv("DEADMAN_S3_PRIMARY_BUCKET", "deadman-primary"),
		S3BackupEndpoint:  os.Getenv("DEADMAN_S3_BACKUP_ENDPOINT"),
		S3BackupBucket:    getenv("DEADMAN_S3_BACKUP_BUCKET", "deadman-backup"),
		S3Region:          getenv("DEADMAN_S3_REGION", "us-east-1"),
		S3AccessKey:       os.Getenv("DEADMAN_S3_ACCESS_KEY"),
		S3SecretKey:       os.Getenv("DEADMAN_S3_SECRET_KEY"),
		S3PathStyle:       getenv("DEADMAN_S3_PATH_STYLE", "true") == "true",

		TLSCertFile:    os.Getenv("DEADMAN_TLS_CERT"),
		TLSKeyFile:     os.Getenv("DEADMAN_TLS_KEY"),
		ReleaseKeyPath:         getenv("DEADMAN_RELEASE_KEY_PATH", "./release-key.pem"),
		VaultPath:              getenv("DEADMAN_VAULT_PATH", "./release-vault.json"),
		VaultPassA:             os.Getenv("DEADMAN_VAULT_PASSPHRASE_A"),
		VaultPassB:             os.Getenv("DEADMAN_VAULT_PASSPHRASE_B"),
		LegacySinglePrivateKey: os.Getenv("DEADMAN_LEGACY_SINGLE_KEY") == "true",

		SMTPHost:         os.Getenv("DEADMAN_SMTP_HOST"),
		SMTPPort:         atoiOr(os.Getenv("DEADMAN_SMTP_PORT"), 587),
		SMTPUsername:     os.Getenv("DEADMAN_SMTP_USERNAME"),
		SMTPPassword:     os.Getenv("DEADMAN_SMTP_PASSWORD"),
		SMTPFrom:         os.Getenv("DEADMAN_SMTP_FROM"),
		SMTPInsecureSkip: os.Getenv("DEADMAN_SMTP_INSECURE_SKIP_VERIFY") == "true",

		BootstrapAdminEmail: strings.ToLower(strings.TrimSpace(os.Getenv("DEADMAN_BOOTSTRAP_ADMIN_EMAIL"))),

		BackupKeepCount: atoiOr(os.Getenv("DEADMAN_BACKUP_KEEP_COUNT"), 14),
	}
	if c.Env != "dev" && c.DatabaseURL == "" {
		return nil, fmt.Errorf("DEADMAN_DATABASE_URL is required outside dev")
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
