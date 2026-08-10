// Package state is the policy lifecycle state machine (§13).
//
// Pure functions: Evaluate(current, event, clock) -> (next, effects). No DB
// access, no time.Now(), no side effects. The caller (scheduler or HTTP
// handler) persists the result and enacts effects. This makes the whole
// lifecycle exhaustively testable with deterministic clocks.
//
// States form a DAG with a few cycles (Warning→Healthy on check-in, etc.).
// The forbidden transitions section below enumerates invariants; any change
// that bypasses them is a bug in the caller, not the machine.
package state

import (
	"fmt"
	"time"
)

// State enumerates lifecycle states. Matches the DB CHECK constraint exactly.
type State string

const (
	Draft         State = "draft"
	Armed         State = "armed"
	Healthy       State = "healthy"
	Warning       State = "warning"
	Grace         State = "grace"
	Hold          State = "hold"
	Triggered     State = "triggered"
	Releasing     State = "releasing"
	Released      State = "released"
	FailedPartial State = "failed_partial"
	Suspended     State = "suspended"
	Revoked       State = "revoked"
)

// EventKind categorizes inputs to the state machine.
type EventKind string

const (
	EventArm             EventKind = "arm"
	EventCheckIn         EventKind = "checkin"
	EventTick            EventKind = "tick" // scheduler heartbeat — checks deadlines
	EventHoldRequested   EventKind = "hold_requested"
	EventHoldCleared     EventKind = "hold_cleared"
	EventSuspend         EventKind = "suspend"
	EventResume          EventKind = "resume"
	EventRevoke          EventKind = "revoke"
	EventReleaseStarted  EventKind = "release_started"
	EventReleaseFinished EventKind = "release_finished"
	EventReleaseFailed   EventKind = "release_failed"
)

// Event is an input to Evaluate. Fields are populated by event kind.
type Event struct {
	Kind EventKind
	// Now is the caller's clock reading. Injected so tests are deterministic.
	Now time.Time
	// ReleaseOK is set on EventReleaseFinished: true = fully released, false = partial.
	ReleaseOK bool
}

// Policy is the subset of PolicyVersion fields the machine needs.
type Policy struct {
	IntervalDays     int
	GracePeriodHours int
	HoldPeriodHours  int
	// WarningLeadHours: how many hours before NextDueAt the state enters Warning.
	// Default 24.
	WarningLeadHours int
}

// Runtime is the mutable state the machine reads and writes.
type Runtime struct {
	State          State
	ArmedAt        *time.Time
	LastCheckInAt  *time.Time
	NextDueAt      *time.Time
	GraceExpiresAt *time.Time
	HoldExpiresAt  *time.Time
	TriggerAt      *time.Time
	Epoch          int64
}

// Effect is a side-effect the machine wants the caller to perform. The
// caller (scheduler, HTTP handler, release worker) interprets these.
type Effect struct {
	Kind    EffectKind
	Message string // free-form context for the caller / audit
}

type EffectKind string

const (
	EffectSendWarning      EffectKind = "send_warning"
	EffectSendOverdue      EffectKind = "send_overdue"
	EffectStartRelease     EffectKind = "start_release"
	EffectNotifyHold       EffectKind = "notify_hold"
	EffectNotifyResume     EffectKind = "notify_resume"
	EffectNotifyRevoked    EffectKind = "notify_revoked"
	EffectNotifySuspended  EffectKind = "notify_suspended"
	EffectAuditStateChange EffectKind = "audit_state_change"
)

// Result bundles the outcome of Evaluate.
type Result struct {
	Runtime Runtime
	Effects []Effect
	// Changed is true if the state transitioned (helpful for the caller to
	// decide whether to persist or short-circuit).
	Changed bool
}

// Evaluate is the whole state machine. Does not mutate inputs.
//
// Invariants:
//   - On EventRevoke from any non-terminal state → Revoked.
//   - Released, Revoked, FailedPartial are terminal for most events; EventTick
//     is a no-op in those states.
//   - Grace cannot be skipped: Warning→Triggered requires time in Grace first.
//   - Hold always delays trigger, never cancels.
func Evaluate(p Policy, rt Runtime, e Event) (Result, error) {
	if err := validatePolicy(p); err != nil {
		return Result{}, err
	}
	out := Result{Runtime: rt}

	// Terminal states accept only manual revival (EventResume) or EventRevoke.
	if isTerminal(rt.State) {
		if e.Kind == EventRevoke && rt.State != Revoked {
			out.Runtime.State = Revoked
			out.Changed = true
			out.Effects = []Effect{{EffectNotifyRevoked, "terminal → revoked"}, {EffectAuditStateChange, string(Revoked)}}
		}
		return out, nil
	}

	switch e.Kind {
	case EventRevoke:
		out.Runtime.State = Revoked
		out.Changed = rt.State != Revoked
		if out.Changed {
			out.Effects = append(out.Effects, Effect{EffectNotifyRevoked, string(rt.State) + " → revoked"})
			out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Revoked)})
		}
		return out, nil

	case EventSuspend:
		if rt.State == Suspended || rt.State == Draft {
			return out, nil
		}
		out.Runtime.State = Suspended
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectNotifySuspended, string(rt.State) + " → suspended"})
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Suspended)})
		return out, nil

	case EventResume:
		if rt.State != Suspended {
			return out, nil
		}
		// Resume re-enters Healthy and resets the next-due window.
		next := e.Now.Add(time.Duration(p.IntervalDays) * 24 * time.Hour)
		out.Runtime.State = Healthy
		out.Runtime.NextDueAt = &next
		out.Runtime.GraceExpiresAt = nil
		out.Runtime.HoldExpiresAt = nil
		out.Runtime.TriggerAt = nil
		out.Runtime.Epoch = rt.Epoch + 1
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectNotifyResume, "suspended → healthy"})
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Healthy)})
		return out, nil

	case EventArm:
		if rt.State != Draft {
			return out, fmt.Errorf("state: cannot arm from %s", rt.State)
		}
		next := e.Now.Add(time.Duration(p.IntervalDays) * 24 * time.Hour)
		armedAt := e.Now
		out.Runtime = Runtime{
			State:     Healthy,
			ArmedAt:   &armedAt,
			NextDueAt: &next,
			Epoch:     rt.Epoch + 1,
		}
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Healthy)})
		return out, nil

	case EventCheckIn:
		if rt.State != Healthy && rt.State != Warning && rt.State != Grace && rt.State != Hold {
			return out, fmt.Errorf("state: cannot check in from %s", rt.State)
		}
		next := e.Now.Add(time.Duration(p.IntervalDays) * 24 * time.Hour)
		now := e.Now
		out.Runtime.State = Healthy
		out.Runtime.LastCheckInAt = &now
		out.Runtime.NextDueAt = &next
		out.Runtime.GraceExpiresAt = nil
		out.Runtime.HoldExpiresAt = nil
		out.Runtime.TriggerAt = nil
		out.Runtime.Epoch = rt.Epoch + 1
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Healthy)})
		return out, nil

	case EventHoldRequested:
		if rt.State != Grace && rt.State != Warning {
			return out, fmt.Errorf("state: hold only valid in warning/grace, got %s", rt.State)
		}
		holdExpires := e.Now.Add(time.Duration(p.HoldPeriodHours) * time.Hour)
		out.Runtime.State = Hold
		out.Runtime.HoldExpiresAt = &holdExpires
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectNotifyHold, fmt.Sprintf("hold until %s", holdExpires.UTC())})
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Hold)})
		return out, nil

	case EventHoldCleared:
		if rt.State != Hold {
			return out, nil
		}
		// Falling out of hold goes to Grace so the countdown continues.
		grace := e.Now.Add(time.Duration(p.GracePeriodHours) * time.Hour)
		out.Runtime.State = Grace
		out.Runtime.GraceExpiresAt = &grace
		out.Runtime.HoldExpiresAt = nil
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Grace)})
		return out, nil

	case EventReleaseStarted:
		if rt.State != Triggered {
			return out, fmt.Errorf("state: release can only start from triggered, got %s", rt.State)
		}
		out.Runtime.State = Releasing
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Releasing)})
		return out, nil

	case EventReleaseFinished:
		if rt.State != Releasing {
			return out, fmt.Errorf("state: release finish requires releasing, got %s", rt.State)
		}
		if e.ReleaseOK {
			out.Runtime.State = Released
		} else {
			out.Runtime.State = FailedPartial
		}
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(out.Runtime.State)})
		return out, nil

	case EventReleaseFailed:
		if rt.State != Releasing {
			return out, fmt.Errorf("state: release failed requires releasing, got %s", rt.State)
		}
		out.Runtime.State = FailedPartial
		out.Changed = true
		out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(FailedPartial)})
		return out, nil

	case EventTick:
		return tick(p, rt, e.Now), nil
	}

	return out, fmt.Errorf("state: unhandled event %s", e.Kind)
}

// tick is the deadline evaluator. Idempotent: running twice with the same
// clock yields the same result.
func tick(p Policy, rt Runtime, now time.Time) Result {
	out := Result{Runtime: rt}
	switch rt.State {
	case Healthy:
		if rt.NextDueAt == nil {
			return out
		}
		// Enter Warning lead hours before due.
		warningStart := rt.NextDueAt.Add(-time.Duration(p.WarningLeadHours) * time.Hour)
		if !now.Before(warningStart) {
			out.Runtime.State = Warning
			out.Changed = true
			out.Effects = append(out.Effects, Effect{EffectSendWarning, "entering warning"})
			out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Warning)})
		}
	case Warning:
		if rt.NextDueAt != nil && !now.Before(*rt.NextDueAt) {
			// Anchor grace at the transition time, not the original due time:
			// after a control-server outage longer than the grace period the
			// user still gets a full grace window after restart instead of an
			// immediate trigger. Matches the Hold→Grace anchoring below.
			grace := now.Add(time.Duration(p.GracePeriodHours) * time.Hour)
			out.Runtime.State = Grace
			out.Runtime.GraceExpiresAt = &grace
			out.Changed = true
			out.Effects = append(out.Effects, Effect{EffectSendOverdue, "entering grace"})
			out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Grace)})
		}
	case Grace:
		if rt.GraceExpiresAt != nil && !now.Before(*rt.GraceExpiresAt) {
			out.Runtime.State = Triggered
			triggerAt := now
			out.Runtime.TriggerAt = &triggerAt
			out.Changed = true
			out.Effects = append(out.Effects, Effect{EffectStartRelease, "grace expired — triggering release"})
			out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Triggered)})
		}
	case Hold:
		if rt.HoldExpiresAt != nil && !now.Before(*rt.HoldExpiresAt) {
			grace := now.Add(time.Duration(p.GracePeriodHours) * time.Hour)
			out.Runtime.State = Grace
			out.Runtime.GraceExpiresAt = &grace
			out.Runtime.HoldExpiresAt = nil
			out.Changed = true
			out.Effects = append(out.Effects, Effect{EffectAuditStateChange, string(Grace)})
		}
	}
	return out
}

func isTerminal(s State) bool {
	switch s {
	case Released, Revoked, FailedPartial:
		return true
	default:
		return false
	}
}

func validatePolicy(p Policy) error {
	if p.IntervalDays < 1 || p.IntervalDays > 365 {
		return fmt.Errorf("state: interval_days out of range (%d)", p.IntervalDays)
	}
	if p.GracePeriodHours < 1 || p.GracePeriodHours > 720 {
		return fmt.Errorf("state: grace_period_hours out of range (%d)", p.GracePeriodHours)
	}
	if p.HoldPeriodHours < 0 {
		return fmt.Errorf("state: hold_period_hours negative")
	}
	if p.WarningLeadHours < 0 {
		return fmt.Errorf("state: warning_lead_hours negative")
	}
	return nil
}
