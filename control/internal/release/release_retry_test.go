package release_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
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

// TestReleaseRetriesFailedDelivery proves the delivery loop retries a
// transient webhook failure across ticks (bounded) and delivers exactly once
// on success — i.e. failed_partial is no longer a dead end and a resumed run
// does not double-deliver.
func TestReleaseRetriesFailedDelivery(t *testing.T) {
	dbURL := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DEADMAN_DATABASE_URL")
	}
	minioURL := os.Getenv("DEADMAN_S3_PRIMARY_ENDPOINT")
	s3Key := os.Getenv("DEADMAN_S3_ACCESS_KEY")
	s3Secret := os.Getenv("DEADMAN_S3_SECRET_KEY")
	if dbURL == "" || minioURL == "" || s3Key == "" {
		t.Skip("need DB + MinIO env")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	primary, err := storage.New(ctx, storage.Config{
		Endpoint: minioURL, Region: "us-east-1",
		Bucket:      "retry-" + uuid.NewString()[:8],
		AccessKeyID: s3Key, SecretAccessKey: s3Secret, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	dw := &storage.DualWriter{Primary: primary}

	relKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	servicePub, servicePriv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(servicePriv)
	clk := &fakeClock{t: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	polSvc := policy.New(s, ledger, clk)

	// Webhook fails (500) on the first hit, succeeds (204) afterward.
	var hits int32
	wh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(wh.Close)

	// Seed user + bundle + webhook destination.
	plaintext := []byte("retry payload")
	manifest := []byte(`{"label":"r"}`)
	mh := crypto.SHA256(manifest)
	ct, wrapped, err := crypto.EncryptBundleForRelease(&relKey.PublicKey, plaintext, mh[:])
	if err != nil {
		t.Fatal(err)
	}
	var userID, bundleID, destID uuid.UUID
	err = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, e := store.CreateUser(ctx, q, "retry-"+uuid.NewString()+"@test.local", "R", nil)
		if e != nil {
			return e
		}
		userID = u.ID
		bundleID = uuid.New()
		objKey := "bundles/" + userID.String() + "/" + bundleID.String() + ".bin"
		if _, e := dw.Put(ctx, objKey, ct, "application/octet-stream"); e != nil {
			return e
		}
		chs := crypto.SHA256(ct)
		if e := insertBundleWithID(ctx, q, &store.ContentBundle{
			ID: bundleID, UserID: userID, Version: 1, Label: "r",
			ManifestHash: mh[:], Manifest: manifest,
			WrappedBundleKey: wrapped, WrapScheme: crypto.SchemeRSAOAEPAESGCM,
			PrimaryURI: primary.URI(objKey), SizeBytes: int64(len(ct)),
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
	_ = destID

	p, _, err := polSvc.Create(ctx, policy.CreateInput{
		UserID: userID, Title: "retry policy",
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

	w := release.New(release.Worker{
		Store: s, Policy: polSvc, Ledger: ledger,
		ReleaseKey: &release.StaticKey{K: relKey}, ServiceSigner: servicePriv, ServicePub: servicePub,
		Storage: dw, Primary: primary, HTTP: wh.Client(),
	})

	// Tick 1 creates the release, moves the policy to 'releasing', and makes
	// the first delivery attempt in the same tick — the webhook 500s, so the
	// release must remain retryable with the policy still 'releasing'.
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("tick1: %v", err)
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "releasing" {
		t.Fatalf("after failed delivery want policy still releasing, got %s", pg.State)
	}
	// Tick 2 retries; the webhook now 204s, so the release completes.
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("tick2: %v", err)
	}
	if pg, _ := store.GetPolicy(ctx, s.Pool, p.ID); pg.State != "released" {
		t.Fatalf("after retry want released, got %s", pg.State)
	}

	// Exactly two webhook hits total (one failed, one ok); no double-delivery.
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("webhook hits = %d, want 2 (1 fail + 1 success)", n)
	}
	// The landing page and bundle are published and readable.
	rid := findReleaseID(ctx, t, s, p.ID)
	rc, err := primary.Get(ctx, "releases/"+rid+"/"+bundleID.String()+".bin")
	if err != nil {
		t.Fatalf("published bundle missing: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != string(plaintext) {
		t.Fatal("published payload mismatch")
	}
}
