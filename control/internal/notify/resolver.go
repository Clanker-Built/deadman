package notify

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	"github.com/gcottrell/deadman/control/internal/crypto"
)

// Resolver returns a fresh Sender built from the effective SMTP config.
// The effective config is (in precedence order):
//
//  1. server_settings row from the DB, where fields are non-null
//  2. the env-derived fallback passed to NewResolver
//
// The SMTP password is taken from the env fallback unless the DB row has
// a wrapped password AND the release private key is currently unlockable
// (via the KeyProvider) — in which case the unwrapped DB password wins.
//
// Output is cached briefly to avoid hammering the DB on every release tick.
type Resolver struct {
	envFallback SMTPConfig
	loader      SettingsLoader
	keys        KeyProvider
	ttl         time.Duration

	mu      sync.Mutex
	cached  *Sender
	fetched time.Time
}

// SettingsLoader abstracts the DB read to avoid importing store here.
type SettingsLoader interface {
	LoadSMTP(ctx context.Context) (db SMTPDBRow, err error)
}

// KeyProvider is the subset of the keyvault.Locker API we need to
// conditionally unwrap the DB-stored password. Passing nil disables the
// DB-password path.
type KeyProvider interface {
	Unlocked() bool
	PrivateKey() *rsa.PrivateKey
}

// SMTPDBRow is the raw settings row. All pointers to make absence explicit.
type SMTPDBRow struct {
	Host             *string
	Port             *int
	Username         *string
	PasswordWrapped  []byte
	From             *string
	InsecureSkip     *bool
}

// NewResolver returns a resolver with 30-second caching.
func NewResolver(env SMTPConfig, loader SettingsLoader, keys KeyProvider) *Resolver {
	return &Resolver{envFallback: env, loader: loader, keys: keys, ttl: 30 * time.Second}
}

// Current returns the effective Sender, or nil if SMTP is not configured.
// Thread-safe. Errors reading DB are logged by the loader's caller and fall
// back to env — returning nil only if env is also disabled.
func (r *Resolver) Current(ctx context.Context) *Sender {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && time.Since(r.fetched) < r.ttl {
		return r.cached
	}
	cfg := r.resolveLocked(ctx)
	if !cfg.Enabled() {
		r.cached = nil
	} else {
		r.cached = NewSender(cfg)
	}
	r.fetched = time.Now()
	return r.cached
}

// Invalidate drops the cache so the next Current() rebuilds from fresh DB
// state. Call from the admin save handler.
func (r *Resolver) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cached = nil
	r.fetched = time.Time{}
}

func (r *Resolver) resolveLocked(ctx context.Context) SMTPConfig {
	eff := r.envFallback
	if r.loader == nil {
		return eff
	}
	row, err := r.loader.LoadSMTP(ctx)
	if err != nil {
		return eff
	}
	if row.Host != nil {
		eff.Host = *row.Host
	}
	if row.Port != nil {
		eff.Port = *row.Port
	}
	if row.Username != nil {
		eff.Username = *row.Username
	}
	if row.From != nil {
		eff.From = *row.From
	}
	if row.InsecureSkip != nil {
		eff.InsecureSkipVerify = *row.InsecureSkip
	}
	if len(row.PasswordWrapped) > 0 && r.keys != nil && r.keys.Unlocked() {
		if pt, err := crypto.UnwrapServerSecret(r.keys.PrivateKey(), row.PasswordWrapped); err == nil {
			eff.Password = string(pt)
		}
	}
	return eff
}

// ErrLocked is returned by wrappers that require an unlocked keyvault.
var ErrLocked = errors.New("notify: vault locked; cannot wrap/unwrap secret")
