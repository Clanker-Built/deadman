// Package policy orchestrates the state machine with the store and audit log.
//
// This is the service layer: all policy operations (create, arm, check in,
// tick, suspend, resume) go through here so that every state transition is
// atomic with its audit event and persisted under optimistic-epoch CAS.
package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/state"
	"github.com/gcottrell/deadman/control/internal/store"
)

// Clock is injectable so tests can run whole lifecycles in ms.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// RealClock is the default production clock.
var RealClock Clock = realClock{}

// Service coordinates policy operations.
type Service struct {
	Store  *store.Store
	Ledger *audit.Ledger
	Clock  Clock
}

func New(s *store.Store, l *audit.Ledger, c Clock) *Service {
	if c == nil {
		c = RealClock
	}
	return &Service{Store: s, Ledger: l, Clock: c}
}

// CreateInput is the first-version policy payload.
type CreateInput struct {
	UserID           uuid.UUID
	Title            string
	Description      string
	IntervalDays     int
	GracePeriodHours int
	HoldPeriodHours  int
	ReleaseMode      string // see DB CHECK
	DestinationIDs   []uuid.UUID
	BundleIDs        []uuid.UUID
	UserSignature    []byte // Ed25519 sig over CanonicalHash by the user's identity key
}

// Create inserts a draft policy and its first signed version.
func (s *Service) Create(ctx context.Context, in CreateInput) (*store.Policy, *store.PolicyVersion, error) {
	var p *store.Policy
	var v *store.PolicyVersion
	err := s.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		var e error
		p, e = store.CreatePolicy(ctx, q, in.UserID, in.Title, in.Description)
		if e != nil {
			return e
		}
		canon := canonicalizePolicy(in, p.ID, 1, s.Clock.Now())
		hash := crypto.SHA256(canon)
		v, e = store.CreatePolicyVersion(ctx, q, &store.PolicyVersion{
			PolicyID:            p.ID,
			IntervalDays:        in.IntervalDays,
			GracePeriodHours:    in.GracePeriodHours,
			HoldPeriodHours:     in.HoldPeriodHours,
			WarningSchedule:     json.RawMessage(`[]`),
			CheckInRequirements: json.RawMessage(`{}`),
			ReleaseMode:         in.ReleaseMode,
			DestinationIDs:      emptyIfNil(in.DestinationIDs),
			ContentBundleIDs:    emptyIfNil(in.BundleIDs),
			EffectiveAt:         s.Clock.Now(),
			UserSignature:       in.UserSignature,
			CanonicalHash:       hash[:],
		})
		if e != nil {
			return e
		}
		_, e = s.Ledger.AppendTx(ctx, q, audit.Event{
			ActorKind:   audit.ActorUser,
			ActorID:     &in.UserID,
			EventType:   "policy.created",
			SubjectKind: "policy",
			SubjectID:   &p.ID,
			Payload: map[string]any{
				"title":              in.Title,
				"interval_days":      in.IntervalDays,
				"grace_period_hours": in.GracePeriodHours,
				"release_mode":       in.ReleaseMode,
				"canonical_hash":     fmt.Sprintf("%x", hash),
			},
		})
		return e
	})
	return p, v, err
}

// Arm transitions the policy from draft → healthy with first due date.
func (s *Service) Arm(ctx context.Context, userID, policyID uuid.UUID) error {
	return s.apply(ctx, userID, policyID, state.Event{Kind: state.EventArm, Now: s.Clock.Now()}, nil)
}

// CheckIn resets a policy's deadline. deviceID may be nil for a browser
// check-in (session-authenticated, no hardware-key signature); the audit
// event then records the user as the actor instead of a device.
func (s *Service) CheckIn(ctx context.Context, userID, policyID uuid.UUID, deviceID *uuid.UUID) error {
	return s.apply(ctx, userID, policyID, state.Event{Kind: state.EventCheckIn, Now: s.Clock.Now()}, deviceID)
}

// CheckInAllArmed applies a check-in to every armed/warning/grace/hold policy
// owned by userID. deviceID nil for browser check-ins.
func (s *Service) CheckInAllArmed(ctx context.Context, userID uuid.UUID, deviceID *uuid.UUID) (int, error) {
	ids, err := store.ListArmedUserPolicyIDs(ctx, s.Store.Pool, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if err := s.CheckIn(ctx, userID, id, deviceID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Suspend / Resume / Revoke are user-triggered transitions.
func (s *Service) Suspend(ctx context.Context, userID, policyID uuid.UUID) error {
	return s.apply(ctx, userID, policyID, state.Event{Kind: state.EventSuspend, Now: s.Clock.Now()}, nil)
}
func (s *Service) Resume(ctx context.Context, userID, policyID uuid.UUID) error {
	return s.apply(ctx, userID, policyID, state.Event{Kind: state.EventResume, Now: s.Clock.Now()}, nil)
}
func (s *Service) Revoke(ctx context.Context, userID, policyID uuid.UUID) error {
	return s.apply(ctx, userID, policyID, state.Event{Kind: state.EventRevoke, Now: s.Clock.Now()}, nil)
}

// UpdateAttachments replaces the bundle and destination lists on a policy's
// active version by writing a new signed policy_version. Allowed only when
// the policy is in draft or suspended — rewiring attachments on an armed
// policy is a rewrite of what "release" means and should require an
// explicit suspend→edit→resume cycle.
//
// Schedule fields (interval_days, grace_period_hours, etc.) are copied from
// the prior version; use a separate API for schedule changes when it
// becomes available. The policy_version chain remains append-only.
func (s *Service) UpdateAttachments(ctx context.Context, userID, policyID uuid.UUID, bundleIDs, destIDs []uuid.UUID) error {
	return s.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		p, err := store.GetPolicy(ctx, q, policyID)
		if err != nil {
			return err
		}
		if p.UserID != userID {
			return fmt.Errorf("policy: not owner")
		}
		if p.State != "draft" && p.State != "suspended" {
			return fmt.Errorf("policy: can only edit attachments when draft or suspended (got %s)", p.State)
		}
		prev, err := store.GetActivePolicyVersion(ctx, q, policyID)
		if err != nil {
			return fmt.Errorf("policy: no prior version: %w", err)
		}
		in := CreateInput{
			UserID:           userID,
			Title:            p.Title,
			Description:      p.Description,
			IntervalDays:     prev.IntervalDays,
			GracePeriodHours: prev.GracePeriodHours,
			HoldPeriodHours:  prev.HoldPeriodHours,
			ReleaseMode:      prev.ReleaseMode,
			DestinationIDs:   destIDs,
			BundleIDs:        bundleIDs,
		}
		canon := canonicalizePolicy(in, policyID, prev.Version+1, s.Clock.Now())
		hash := crypto.SHA256(canon)
		v, err := store.CreatePolicyVersion(ctx, q, &store.PolicyVersion{
			PolicyID:            policyID,
			IntervalDays:        in.IntervalDays,
			GracePeriodHours:    in.GracePeriodHours,
			HoldPeriodHours:     in.HoldPeriodHours,
			WarningSchedule:     prev.WarningSchedule,
			CheckInRequirements: prev.CheckInRequirements,
			ReleaseMode:         in.ReleaseMode,
			DestinationIDs:      emptyIfNil(destIDs),
			ContentBundleIDs:    emptyIfNil(bundleIDs),
			EffectiveAt:         s.Clock.Now(),
			UserSignature:       make([]byte, 64), // placeholder until client-side signing
			CanonicalHash:       hash[:],
		})
		if err != nil {
			return err
		}
		_, err = s.Ledger.AppendTx(ctx, q, audit.Event{
			ActorKind:   audit.ActorUser,
			ActorID:     &userID,
			EventType:   "policy.attachments_updated",
			SubjectKind: "policy",
			SubjectID:   &policyID,
			Payload: map[string]any{
				"new_version":       v.Version,
				"bundle_count":      len(bundleIDs),
				"destination_count": len(destIDs),
			},
		})
		return err
	})
}

// ForceTriggerDev is a development-only helper that rewinds a policy's
// deadlines into the past so the next scheduler tick transitions
// healthy → warning → grace → triggered immediately. Use via the dev UI
// button or curl; never exposed in production builds.
func (s *Service) ForceTriggerDev(ctx context.Context, userID, policyID uuid.UUID) error {
	return s.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		p, err := store.GetPolicy(ctx, q, policyID)
		if err != nil {
			return err
		}
		if userID != uuid.Nil && p.UserID != userID {
			return fmt.Errorf("policy: not owner")
		}
		past := s.Clock.Now().Add(-time.Hour)
		_, err = q.Exec(ctx,
			`UPDATE policy_states
			 SET next_due_at = $2, grace_expires_at = $2, hold_expires_at = NULL,
			     updated_at = now()
			 WHERE policy_id = $1`, policyID, past)
		return err
	})
}

// ReleaseStarted transitions a triggered policy to releasing. Called by the
// release worker right after it creates the release_transactions row.
func (s *Service) ReleaseStarted(ctx context.Context, policyID uuid.UUID) error {
	return s.apply(ctx, uuid.Nil, policyID, state.Event{Kind: state.EventReleaseStarted, Now: s.Clock.Now()}, nil)
}

// ReleaseFinished transitions releasing → released or failed_partial.
func (s *Service) ReleaseFinished(ctx context.Context, policyID uuid.UUID, ok bool) error {
	return s.apply(ctx, uuid.Nil, policyID, state.Event{Kind: state.EventReleaseFinished, Now: s.Clock.Now(), ReleaseOK: ok}, nil)
}

// Tick is used by the scheduler: evaluates deadlines and advances if needed.
// No owner check here because the scheduler is a system actor.
func (s *Service) Tick(ctx context.Context, policyID uuid.UUID) (bool, error) {
	changed := false
	err := s.apply(ctx, uuid.Nil, policyID, state.Event{Kind: state.EventTick, Now: s.Clock.Now()}, nil)
	if err == nil {
		// apply doesn't distinguish — but the caller of Tick typically just cares it didn't error.
		changed = true
	}
	return changed, err
}

// apply loads policy + runtime, runs Evaluate, persists + audits inside one
// serializable transaction with epoch CAS.
func (s *Service) apply(ctx context.Context, userID, policyID uuid.UUID, ev state.Event, deviceID *uuid.UUID) error {
	return s.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		p, err := store.GetPolicy(ctx, q, policyID)
		if err != nil {
			return err
		}
		if userID != uuid.Nil && p.UserID != userID {
			return fmt.Errorf("policy: not owner")
		}
		v, err := store.GetActivePolicyVersion(ctx, q, policyID)
		if err != nil && ev.Kind != state.EventArm {
			return fmt.Errorf("policy: no active version: %w", err)
		}
		ps, err := store.GetPolicyState(ctx, q, policyID)
		if err != nil {
			return err
		}

		// Build state.Policy from version (or sensible defaults pre-arm).
		var sp state.Policy
		if v != nil {
			sp = state.Policy{
				IntervalDays:     v.IntervalDays,
				GracePeriodHours: v.GracePeriodHours,
				HoldPeriodHours:  v.HoldPeriodHours,
				WarningLeadHours: 24,
			}
		} else {
			sp = state.Policy{IntervalDays: 14, GracePeriodHours: 72, HoldPeriodHours: 48, WarningLeadHours: 24}
		}

		rt := state.Runtime{
			State:          state.State(p.State),
			ArmedAt:        ps.ArmedAt,
			LastCheckInAt:  ps.LastCheckInAt,
			NextDueAt:      ps.NextDueAt,
			GraceExpiresAt: ps.GraceExpiresAt,
			HoldExpiresAt:  ps.HoldExpiresAt,
			TriggerAt:      ps.TriggerAt,
			Epoch:          ps.Epoch,
		}

		result, err := state.Evaluate(sp, rt, ev)
		if err != nil {
			return err
		}
		if !result.Changed {
			return nil
		}

		// Persist runtime.
		newPS := &store.PolicyState{
			PolicyID:       policyID,
			ArmedAt:        result.Runtime.ArmedAt,
			LastCheckInAt:  result.Runtime.LastCheckInAt,
			NextDueAt:      result.Runtime.NextDueAt,
			GraceExpiresAt: result.Runtime.GraceExpiresAt,
			HoldExpiresAt:  result.Runtime.HoldExpiresAt,
			TriggerAt:      result.Runtime.TriggerAt,
			Epoch:          result.Runtime.Epoch + 1,
		}
		if err := store.UpdatePolicyStateCAS(ctx, q, newPS, ps.Epoch, string(result.Runtime.State), deviceID); err != nil {
			return err
		}

		// Audit.
		actor := audit.ActorUser
		var actorID *uuid.UUID
		switch {
		case ev.Kind == state.EventTick:
			actor = audit.ActorSystem
		case ev.Kind == state.EventCheckIn && deviceID != nil:
			actor = audit.ActorDevice
			actorID = deviceID
		default:
			if userID != uuid.Nil {
				uid := userID
				actorID = &uid
			}
		}
		_, err = s.Ledger.AppendTx(ctx, q, audit.Event{
			ActorKind:   actor,
			ActorID:     actorID,
			EventType:   "policy.state_transition",
			SubjectKind: "policy",
			SubjectID:   &policyID,
			Payload: map[string]any{
				"from":       p.State,
				"to":         string(result.Runtime.State),
				"event":      string(ev.Kind),
				"epoch":      newPS.Epoch,
				"effects":    effectNames(result.Effects),
				"trigger_at": result.Runtime.TriggerAt,
			},
		})
		return err
	})
}

// canonicalizePolicy returns the stable byte representation a user signs over
// when creating or mutating a policy version. Field order fixed here.
func canonicalizePolicy(in CreateInput, policyID uuid.UUID, version int, at time.Time) []byte {
	type canon struct {
		PolicyID         uuid.UUID   `json:"policy_id"`
		Version          int         `json:"version"`
		Title            string      `json:"title"`
		Description      string      `json:"description"`
		IntervalDays     int         `json:"interval_days"`
		GracePeriodHours int         `json:"grace_period_hours"`
		HoldPeriodHours  int         `json:"hold_period_hours"`
		ReleaseMode      string      `json:"release_mode"`
		DestinationIDs   []uuid.UUID `json:"destination_ids"`
		BundleIDs        []uuid.UUID `json:"bundle_ids"`
		EffectiveAt      time.Time   `json:"effective_at"`
	}
	b, err := json.Marshal(canon{
		PolicyID:         policyID,
		Version:          version,
		Title:            in.Title,
		Description:      in.Description,
		IntervalDays:     in.IntervalDays,
		GracePeriodHours: in.GracePeriodHours,
		HoldPeriodHours:  in.HoldPeriodHours,
		ReleaseMode:      in.ReleaseMode,
		DestinationIDs:   emptyIfNil(in.DestinationIDs),
		BundleIDs:        emptyIfNil(in.BundleIDs),
		EffectiveAt:      at.UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		panic(err)
	}
	return b
}

func emptyIfNil(a []uuid.UUID) []uuid.UUID {
	if a == nil {
		return []uuid.UUID{}
	}
	return a
}

func effectNames(effs []state.Effect) []string {
	out := make([]string, 0, len(effs))
	for _, e := range effs {
		out = append(out, string(e.Kind))
	}
	return out
}

// VerifyPolicySignature checks the user_signature over canonical_hash with
// the user's identity pubkey. Call this at create/mutate time.
func VerifyPolicySignature(identityPub ed25519.PublicKey, canonicalHash, signature []byte) bool {
	return crypto.VerifyEd25519(identityPub, canonicalHash, signature)
}
