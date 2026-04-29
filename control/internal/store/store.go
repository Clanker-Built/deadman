// Package store is the thin DB access layer over pgx. Each subpackage-less
// repository function takes a context and either a *pgxpool.Pool or a
// pgx.Tx (via the Querier interface) so they compose in transactions.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the subset of pgx methods we use. Both *pgxpool.Pool and pgx.Tx
// satisfy it, which lets every repo method run either in its own pooled
// connection or inside an existing transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store wraps a pgx pool.
type Store struct {
	Pool *pgxpool.Pool
}

// New opens a pool, pings, and returns a ready Store.
func New(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

// InTx runs fn inside a ReadCommitted transaction. fn receives a Querier
// that is the pgx.Tx. Commit on nil error, rollback otherwise.
//
// We choose ReadCommitted because every contended path in this codebase uses
// explicit row locks (FOR UPDATE on the audit-chain tip) or optimistic CAS
// (policy_states.epoch). Serializable added spurious 40001 aborts under
// parallel tests without buying any real correctness here.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context, q Querier) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ErrNotFound is returned when a lookup yields no rows.
var ErrNotFound = errors.New("store: not found")

// IsNotFound maps pgx.ErrNoRows to ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}
