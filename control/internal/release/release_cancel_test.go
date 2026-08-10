package release_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/release"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// TestRevokeCancelsStalledRelease reproduces the critical finding: a policy
// triggers, the release stalls because the keyvault is locked, the owner
// revokes, and the vault later unlocks. The release must NOT fire. Only the
// DB is required — the release never advances to unseal/publish, so no object
// storage is touched.
func TestRevokeCancelsStalledRelease(t *testing.T) {
	dbURL := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DEADMAN_DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("need DEADMAN_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	servicePub, servicePriv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(servicePriv)
	clk := &fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	polSvc := policy.New(s, ledger, clk)

	// Webhook that must never be hit.
	var whHits int32
	wh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&whHits, 1)
		w.WriteHeader(204)
	}))
	t.Cleanup(wh.Close)

	// Seed user + a bundle row + a webhook destination + an armed policy.
	var userID, bundleID, destID uuid.UUID
	relKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	err = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, e := store.CreateUser(ctx, q, "cancel-"+uuid.NewString()+"@test.local", "Cancel", nil)
		if e != nil {
			return e
		}
		userID = u.ID
		// A bundle row is needed so the policy version references something,
		// but its ciphertext is never fetched (release is canceled first).
		bundleID = uuid.New()
		manifest := []byte(`{"label":"c"}`)
		mh := crypto.SHA256(manifest)
		ct, wrapped, e := crypto.EncryptBundleForRelease(&relKey.PublicKey, []byte("secret"), mh[:])
		if e != nil {
			return e
		}
		chs := crypto.SHA256(ct)
		if e := insertBundleWithID(ctx, q, &store.ContentBundle{
			ID: bundleID, UserID: userID, Version: 1, Label: "c",
			ManifestHash: mh[:], Manifest: manifest,
			WrappedBundleKey: wrapped, WrapScheme: crypto.SchemeRSAOAEPAESGCM,
			PrimaryURI: "s3://bucket/never-read", SizeBytes: int64(len(ct)),
			CiphertextSHA256: chs[:],
		}); e != nil {
			return e
		}
		cfg, _ := json.Marshal(map[string]string{"url": wh.URL})
		d, e := store.CreateDestination(ctx, q, &store.Destination{
			UserID: userID, Kind: "webhook", Label: "wh", Config: cfg,
		})
		if e != nil {
			return e
		}
		destID = d.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) })

	p, _, err := polSvc.Create(ctx, policy.CreateInput{
		UserID: userID, Title: "cancel policy",
		IntervalDays: 14, GracePeriodHours: 72, ReleaseMode: "limited_public",
		DestinationIDs: []uuid.UUID{destID}, BundleIDs: []uuid.UUID{bundleID},
		UserSignature: make([]byte, ed25519.SignatureSize),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := polSvc.Arm(ctx, userID, p.ID); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{14*24*time.Hour - 23*time.Hour, 24 * time.Hour, 73 * time.Hour} {
		clk.Advance(d)
		if _, err := polSvc.Tick(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "triggered" {
		t.Fatalf("want triggered, got %s", pg.State)
	}

	// Vault locked (K=nil): Tick creates the release transaction and moves the
	// policy to releasing, but cannot advance — the stall.
	locked := &release.StaticKey{K: nil}
	w := release.New(release.Worker{
		Store: s, Policy: polSvc, Ledger: ledger,
		ReleaseKey: locked, ServiceSigner: servicePriv, ServicePub: servicePub,
		Storage: &storage.DualWriter{}, HTTP: wh.Client(),
	})
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("stalled tick: %v", err)
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "releasing" {
		t.Fatalf("want releasing after create, got %s", pg.State)
	}

	// Owner returns alive and revokes.
	if err := polSvc.Revoke(ctx, userID, p.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "revoked" {
		t.Fatalf("want revoked, got %s", pg.State)
	}
	var rtState string
	if err := s.Pool.QueryRow(ctx,
		`SELECT state FROM release_transactions WHERE policy_id = $1`, p.ID).Scan(&rtState); err != nil {
		t.Fatal(err)
	}
	if rtState != "canceled" {
		t.Fatalf("release transaction should be canceled after revoke, got %s", rtState)
	}

	// Vault unlocks. The release must stay canceled and never deliver.
	locked.K = relKey
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("post-unlock tick: %v", err)
	}
	if n := atomic.LoadInt32(&whHits); n != 0 {
		t.Fatalf("webhook fired %d times after revoke; content was released despite recall", n)
	}
	if err := s.Pool.QueryRow(ctx,
		`SELECT state FROM release_transactions WHERE policy_id = $1`, p.ID).Scan(&rtState); err != nil {
		t.Fatal(err)
	}
	if rtState != "canceled" {
		t.Fatalf("release transaction changed after unlock: %s", rtState)
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "revoked" {
		t.Fatalf("policy state changed after unlock: %s", pg.State)
	}
}
