package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestReleaseStateGuardsRejectAfterCancel proves the TOCTOU fix: once a
// release is canceled (as a revoke does mid-flight), the worker's forward
// state advances and its finalize both report "no rows" and therefore cannot
// resurrect the release or overwrite the cancel with 'completed'.
func TestReleaseStateGuardsRejectAfterCancel(t *testing.T) {
	s := requireDB(t)
	ctx := context.Background()

	var releaseID, policyID uuid.UUID
	err := s.InTx(ctx, func(ctx context.Context, q Querier) error {
		u, e := CreateUser(ctx, q, "guard-"+uuid.NewString()+"@test.local", "G", nil)
		if e != nil {
			return e
		}
		p, e := CreatePolicy(ctx, q, u.ID, "guard", "")
		if e != nil {
			return e
		}
		policyID = p.ID
		v, e := CreatePolicyVersion(ctx, q, &PolicyVersion{
			PolicyID: p.ID, IntervalDays: 14, GracePeriodHours: 72,
			WarningSchedule: []byte(`[]`), CheckInRequirements: []byte(`{}`),
			ReleaseMode: "limited_public", DestinationIDs: []uuid.UUID{}, ContentBundleIDs: []uuid.UUID{},
			UserSignature: make([]byte, 64), CanonicalHash: make([]byte, 32),
		})
		if e != nil {
			return e
		}
		rt, _, e := CreateOrGetReleaseTransaction(ctx, q, p.ID, v.ID, 1)
		if e != nil {
			return e
		}
		releaseID = rt.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), `DELETE FROM policies WHERE id = $1`, policyID) })

	// Advance to 'publishing' (worker in flight) — the guard allows this from
	// an active state.
	if ok, err := UpdateReleaseState(ctx, s.Pool, releaseID, "publishing"); err != nil || !ok {
		t.Fatalf("advance to publishing: ok=%v err=%v", ok, err)
	}

	// A revoke lands: cancel the open release.
	if n, err := CancelOpenReleasesForPolicy(ctx, s.Pool, policyID); err != nil || n != 1 {
		t.Fatalf("cancel: n=%d err=%v", n, err)
	}

	// Every subsequent worker write must now no-op (report false), so the
	// cancel wins and nothing is published or marked completed.
	if ok, err := UpdateReleaseState(ctx, s.Pool, releaseID, "unsealing"); err != nil || ok {
		t.Fatalf("advance after cancel should no-op: ok=%v err=%v", ok, err)
	}
	if ok, err := FinishRelease(ctx, s.Pool, releaseID, "completed", []byte(`{}`), []byte("sig")); err != nil || ok {
		t.Fatalf("finish after cancel should no-op: ok=%v err=%v", ok, err)
	}

	// State stayed canceled.
	var st string
	if err := s.Pool.QueryRow(ctx, `SELECT state FROM release_transactions WHERE id = $1`, releaseID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "canceled" {
		t.Fatalf("release state = %s, want canceled", st)
	}
}
