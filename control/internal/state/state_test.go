package state

import (
	"testing"
	"time"
)

var defaultPolicy = Policy{
	IntervalDays:     14,
	GracePeriodHours: 72,
	HoldPeriodHours:  48,
	WarningLeadHours: 24,
}

func t0() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func TestArmHealthyCheckInLoop(t *testing.T) {
	rt := Runtime{State: Draft}
	// Arm
	r, err := Evaluate(defaultPolicy, rt, Event{Kind: EventArm, Now: t0()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Runtime.State != Healthy {
		t.Fatalf("want healthy, got %s", r.Runtime.State)
	}
	rt = r.Runtime

	// Tick immediately — still healthy.
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventTick, Now: t0()})
	if r.Runtime.State != Healthy {
		t.Fatalf("want healthy, got %s", r.Runtime.State)
	}

	// Tick just before warning lead — still healthy.
	beforeWarn := t0().Add(14*24*time.Hour - 25*time.Hour)
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventTick, Now: beforeWarn})
	if r.Runtime.State != Healthy {
		t.Fatalf("want healthy at %v, got %s", beforeWarn, r.Runtime.State)
	}

	// Tick inside warning window — transitions to Warning.
	warn := t0().Add(14*24*time.Hour - 23*time.Hour)
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventTick, Now: warn})
	if r.Runtime.State != Warning {
		t.Fatalf("want warning, got %s", r.Runtime.State)
	}
	if len(r.Effects) == 0 {
		t.Fatal("warning transition produced no effects")
	}
	rt = r.Runtime

	// Check-in during warning resets to healthy with new deadline.
	checkin := warn.Add(time.Hour)
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventCheckIn, Now: checkin})
	if r.Runtime.State != Healthy {
		t.Fatal("check-in didn't return to healthy")
	}
	if r.Runtime.NextDueAt.Before(checkin.Add(13 * 24 * time.Hour)) {
		t.Fatal("next due wasn't reset")
	}
}

func TestFullLifecycleMissedCheckInTriggersRelease(t *testing.T) {
	p := defaultPolicy
	rt := Runtime{State: Draft}
	// Arm at t0
	r, _ := Evaluate(p, rt, Event{Kind: EventArm, Now: t0()})
	rt = r.Runtime
	// Tick into Warning
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: t0().Add(14*24*time.Hour - time.Hour)})
	if r.Runtime.State != Warning {
		t.Fatalf("want warning, got %s", r.Runtime.State)
	}
	rt = r.Runtime
	// Pass the due date → Grace
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: t0().Add(14*24*time.Hour + time.Minute)})
	if r.Runtime.State != Grace {
		t.Fatalf("want grace, got %s", r.Runtime.State)
	}
	if r.Runtime.GraceExpiresAt == nil {
		t.Fatal("grace expiry not set")
	}
	rt = r.Runtime
	// Grace expires → Triggered
	past := rt.GraceExpiresAt.Add(time.Minute)
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: past})
	if r.Runtime.State != Triggered {
		t.Fatalf("want triggered, got %s", r.Runtime.State)
	}
	if hasEffect(r.Effects, EffectStartRelease) == false {
		t.Fatal("no start_release effect emitted")
	}
	rt = r.Runtime
	// Release pipeline
	r, _ = Evaluate(p, rt, Event{Kind: EventReleaseStarted, Now: past.Add(time.Second)})
	if r.Runtime.State != Releasing {
		t.Fatal("not releasing")
	}
	rt = r.Runtime
	r, _ = Evaluate(p, rt, Event{Kind: EventReleaseFinished, Now: past.Add(time.Minute), ReleaseOK: true})
	if r.Runtime.State != Released {
		t.Fatalf("want released, got %s", r.Runtime.State)
	}
}

func TestHoldDelaysButDoesNotCancel(t *testing.T) {
	p := defaultPolicy
	rt := Runtime{State: Draft}
	r, _ := Evaluate(p, rt, Event{Kind: EventArm, Now: t0()})
	rt = r.Runtime
	// Into Grace.
	afterDue := t0().Add(14*24*time.Hour + time.Minute)
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: t0().Add(14*24*time.Hour - time.Hour)})
	rt = r.Runtime
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: afterDue})
	rt = r.Runtime
	if rt.State != Grace {
		t.Fatalf("setup: expected grace, got %s", rt.State)
	}
	// Trusted contact puts policy on Hold.
	r, _ = Evaluate(p, rt, Event{Kind: EventHoldRequested, Now: afterDue.Add(time.Hour)})
	if r.Runtime.State != Hold {
		t.Fatalf("want hold, got %s", r.Runtime.State)
	}
	rt = r.Runtime

	// Tick while on hold — still hold.
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: afterDue.Add(time.Hour)})
	if r.Runtime.State != Hold {
		t.Fatal("hold ended prematurely")
	}

	// Hold expires → back to Grace, restart grace countdown.
	past := rt.HoldExpiresAt.Add(time.Minute)
	r, _ = Evaluate(p, rt, Event{Kind: EventTick, Now: past})
	if r.Runtime.State != Grace {
		t.Fatalf("want grace after hold expiry, got %s", r.Runtime.State)
	}
}

func TestTerminalStatesAreTerminal(t *testing.T) {
	rt := Runtime{State: Released}
	r, err := Evaluate(defaultPolicy, rt, Event{Kind: EventCheckIn, Now: t0()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Runtime.State != Released || r.Changed {
		t.Fatal("check-in mutated a terminal state")
	}
	// Revoke from a terminal is allowed (for cleanup).
	rt = Runtime{State: FailedPartial}
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventRevoke, Now: t0()})
	if r.Runtime.State != Revoked {
		t.Fatalf("failed_partial → revoke should move to revoked, got %s", r.Runtime.State)
	}
}

func TestCannotArmTwice(t *testing.T) {
	rt := Runtime{State: Healthy}
	if _, err := Evaluate(defaultPolicy, rt, Event{Kind: EventArm, Now: t0()}); err == nil {
		t.Fatal("re-arming from healthy should be rejected")
	}
}

func TestSuspendResume(t *testing.T) {
	rt := Runtime{State: Draft}
	r, _ := Evaluate(defaultPolicy, rt, Event{Kind: EventArm, Now: t0()})
	rt = r.Runtime
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventSuspend, Now: t0()})
	if r.Runtime.State != Suspended {
		t.Fatal("not suspended")
	}
	rt = r.Runtime
	// Tick while suspended — nothing happens.
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventTick, Now: t0().Add(100 * 24 * time.Hour)})
	if r.Runtime.State != Suspended {
		t.Fatal("tick changed suspended state")
	}
	// Resume → healthy with fresh deadline.
	r, _ = Evaluate(defaultPolicy, rt, Event{Kind: EventResume, Now: t0().Add(100 * 24 * time.Hour)})
	if r.Runtime.State != Healthy {
		t.Fatalf("want healthy after resume, got %s", r.Runtime.State)
	}
}

func TestPolicyValidation(t *testing.T) {
	cases := []Policy{
		{IntervalDays: 0, GracePeriodHours: 72},
		{IntervalDays: 366, GracePeriodHours: 72},
		{IntervalDays: 14, GracePeriodHours: 0},
		{IntervalDays: 14, GracePeriodHours: 721},
		{IntervalDays: 14, GracePeriodHours: 72, HoldPeriodHours: -1},
	}
	for i, p := range cases {
		if _, err := Evaluate(p, Runtime{State: Draft}, Event{Kind: EventArm, Now: t0()}); err == nil {
			t.Fatalf("case %d: want error, got nil", i)
		}
	}
}

func hasEffect(effs []Effect, k EffectKind) bool {
	for _, e := range effs {
		if e.Kind == k {
			return true
		}
	}
	return false
}
