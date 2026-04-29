// Package scheduler is the trigger evaluator. A single goroutine wakes up on
// a tick, selects armed policies whose deadlines may have passed, and runs
// the state-machine Tick event for each.
//
// Concurrency: selection uses FOR UPDATE SKIP LOCKED so multiple schedulers
// can run safely (M4 horizontal scaling). Each policy's transition is
// serializable-isolated by policy.Service.
//
// Determinism: the clock is injected so integration tests can compress a
// 14-day lifecycle into milliseconds.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/store"
)

// Config tunes the scheduler.
type Config struct {
	// Interval is how often the scheduler wakes. Default 30s.
	Interval time.Duration
	// BatchSize is the max policies evaluated per tick. Default 100.
	BatchSize int
}

// OnTick is an optional hook called after every successful tick. Used by the
// watchdog heartbeat so an external prober can detect silent failure.
type OnTick func()

// Scheduler runs the tick loop.
type Scheduler struct {
	cfg    Config
	svc    *policy.Service
	store  *store.Store
	logger *slog.Logger
	onTick OnTick
}

func New(cfg Config, svc *policy.Service, s *store.Store, logger *slog.Logger) *Scheduler {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{cfg: cfg, svc: svc, store: s, logger: logger}
}

// SetOnTick registers a hook fired after each successful tick.
func (s *Scheduler) SetOnTick(h OnTick) { s.onTick = h }

// Run blocks until ctx is canceled. Runs one tick immediately at startup so
// missed deadlines during downtime are picked up without waiting a full cycle.
func (s *Scheduler) Run(ctx context.Context) error {
	s.logger.Info("scheduler starting", "interval", s.cfg.Interval, "batch_size", s.cfg.BatchSize)
	if err := s.Tick(ctx); err != nil {
		s.logger.Error("initial tick", "err", err)
	}
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopping")
			return nil
		case <-t.C:
			if err := s.Tick(ctx); err != nil {
				s.logger.Error("tick", "err", err)
			}
		}
	}
}

// Tick executes one selection+evaluation pass. Exposed for tests so they can
// drive the scheduler deterministically with an injected clock.
func (s *Scheduler) Tick(ctx context.Context) error {
	ids, err := s.selectDue(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.svc.Tick(ctx, id); err != nil {
			s.logger.Warn("policy tick", "policy_id", id, "err", err)
		}
	}
	if s.onTick != nil {
		s.onTick()
	}
	return nil
}

func (s *Scheduler) selectDue(ctx context.Context) ([]uuid.UUID, error) {
	// The FOR UPDATE lock must live inside a tx.
	var ids []uuid.UUID
	err := s.store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		var e error
		ids, e = store.SelectDuePolicyIDs(ctx, q, s.svc.Clock.Now(), s.cfg.BatchSize)
		return e
	})
	return ids, err
}
