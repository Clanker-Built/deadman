package release_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// TestReleaseEndToEnd: arm a policy with a bundle + a webhook destination,
// miss all check-ins, let the scheduler drive state to triggered, then run
// the release worker. Verify: landing/manifest/payload uploaded to storage,
// webhook received signed POST, state advances to released.
func TestReleaseEndToEnd(t *testing.T) {
	dbURL := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DEADMAN_DATABASE_URL")
	}
	minioURL := os.Getenv("DEADMAN_S3_PRIMARY_ENDPOINT")
	s3Key := os.Getenv("DEADMAN_S3_ACCESS_KEY")
	s3Secret := os.Getenv("DEADMAN_S3_SECRET_KEY")
	if dbURL == "" || minioURL == "" || s3Key == "" {
		t.Skip("need DB + MinIO env (DEADMAN_TEST_DATABASE_URL, DEADMAN_S3_*)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	// Object storage (single bucket for tests; backup reuses primary).
	primary, err := storage.New(ctx, storage.Config{
		Endpoint: minioURL, Region: "us-east-1",
		Bucket:      "deadman-e2e-" + uuid.NewString()[:8],
		AccessKeyID: s3Key, SecretAccessKey: s3Secret, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	dw := &storage.DualWriter{Primary: primary}

	// Release key.
	relKey, err := crypto.LoadOrCreateReleaseKey(filepath.Join(t.TempDir(), "rel.pem"))
	if err != nil {
		t.Fatal(err)
	}

	// Service signer (audit + manifest).
	servicePub, servicePriv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(servicePriv)

	// Fake clock for deterministic lifecycle.
	clk := &fakeClock{t: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	polSvc := policy.New(s, ledger, clk)

	// Webhook receiver.
	var whHits int32
	var lastBody []byte
	var lastSig string
	wh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody = body
		lastSig = r.Header.Get("X-Deadman-Signature")
		atomic.AddInt32(&whHits, 1)
		w.WriteHeader(204)
	}))
	t.Cleanup(wh.Close)

	// Seed user + bundle + destination + policy with references.
	email := "e2e-" + uuid.NewString() + "@test.local"
	var userID uuid.UUID
	err = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, e := store.CreateUser(ctx, q, email, "E2E", nil)
		if e != nil {
			return e
		}
		userID = u.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	// Encrypt a payload directly against the release pubkey (simulating the browser flow).
	plaintext := []byte("confidential evidence 🔥")
	manifest := []byte(`{"label":"e2e","file_count":1}`)
	manifestHash := crypto.SHA256(manifest)
	ct, wrapped, err := crypto.EncryptBundleForRelease(&relKey.PublicKey, plaintext, manifestHash[:])
	if err != nil {
		t.Fatal(err)
	}
	// Upload ciphertext to primary storage.
	bundleID := uuid.New()
	objKey := "bundles/" + userID.String() + "/" + bundleID.String() + ".bin"
	if _, err := dw.Put(ctx, objKey, ct, "application/octet-stream"); err != nil {
		t.Fatal(err)
	}

	var destID uuid.UUID
	err = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		b := &store.ContentBundle{
			ID: bundleID, UserID: userID, Version: 1,
			Label:        "e2e-bundle",
			ManifestHash: manifestHash[:], Manifest: manifest,
			WrappedBundleKey: wrapped, WrapScheme: crypto.SchemeRSAOAEPAESGCM,
			PrimaryURI: primary.URI(objKey), SizeBytes: int64(len(ct)),
			CiphertextSHA256: (func() []byte { h := crypto.SHA256(ct); return h[:] })(),
		}
		if e := insertBundleWithID(ctx, q, b); e != nil {
			return e
		}
		cfg, _ := json.Marshal(map[string]string{"url": wh.URL})
		d, e := store.CreateDestination(ctx, q, &store.Destination{
			UserID: userID, Kind: "webhook", Label: "e2e webhook", Config: cfg,
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

	// Create policy with the bundle + destination attached.
	p, _, err := polSvc.Create(ctx, policy.CreateInput{
		UserID: userID, Title: "e2e policy",
		IntervalDays: 14, GracePeriodHours: 72,
		ReleaseMode:    "limited_public",
		DestinationIDs: []uuid.UUID{destID},
		BundleIDs:      []uuid.UUID{bundleID},
		UserSignature:  make([]byte, ed25519.SignatureSize),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := polSvc.Arm(ctx, userID, p.ID); err != nil {
		t.Fatal(err)
	}

	// Drive the state machine past grace via fast ticks.
	for _, d := range []time.Duration{
		14*24*time.Hour - 23*time.Hour, // healthy -> warning
		24 * time.Hour,                 // warning -> grace (now = due + 1h)
		73 * time.Hour,                 // grace -> triggered
	} {
		clk.Advance(d)
		if _, err := polSvc.Tick(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}

	// At this point state should be 'triggered'.
	pg, _ := store.GetPolicy(ctx, s.Pool, p.ID)
	if pg.State != "triggered" {
		t.Fatalf("want triggered, got %s", pg.State)
	}

	// Run the release worker.
	w := release.New(release.Worker{
		Store: s, Policy: polSvc, Ledger: ledger,
		ReleaseKey: &release.StaticKey{K: relKey}, ServiceSigner: servicePriv, ServicePub: servicePub,
		Storage: dw, Primary: primary,
	})
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("release tick 1 (create tx + state to releasing): %v", err)
	}
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("release tick 2 (run pipeline): %v", err)
	}

	// State should now be 'released'.
	pg, _ = store.GetPolicy(ctx, s.Pool, p.ID)
	if pg.State != "released" {
		t.Fatalf("want released, got %s", pg.State)
	}

	// Webhook should have fired exactly once with a valid signature.
	if atomic.LoadInt32(&whHits) != 1 {
		t.Fatalf("webhook hits = %d, want 1", whHits)
	}
	if lastSig == "" {
		t.Fatal("webhook missing signature header")
	}
	sig := decodeB64URL(t, lastSig)
	if !ed25519.Verify(servicePub, lastBody, sig) {
		t.Fatal("webhook signature failed to verify")
	}
	var payload struct {
		PublicURL string `json:"public_url"`
	}
	if err := json.Unmarshal(lastBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.PublicURL == "" {
		t.Fatal("no public_url in webhook")
	}

	// The landing page + manifest + signed bundle should all be in the bucket.
	for _, rel := range []string{"index.html", "manifest.json", "manifest.sig", bundleID.String() + ".bin"} {
		key := "releases/" + findReleaseID(ctx, t, s, p.ID) + "/" + rel
		rc, err := primary.Get(ctx, key)
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if len(b) == 0 {
			t.Fatalf("empty %s", rel)
		}
		if rel == bundleID.String()+".bin" && !bytes.Equal(b, plaintext) {
			t.Fatal("released payload does not match original plaintext")
		}
	}
}

func decodeB64URL(t *testing.T, s string) []byte {
	t.Helper()
	// Match base64URLNoPad (RFC 4648 unpadded).
	for len(s)%4 != 0 {
		s += "="
	}
	// Use stdlib-ish decode via translating chars.
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	rev := make(map[byte]byte, 64)
	for i := 0; i < len(alpha); i++ {
		rev[alpha[i]] = byte(i)
	}
	var out []byte
	for i := 0; i+4 <= len(s); i += 4 {
		var v uint32
		for j := 0; j < 4; j++ {
			if s[i+j] == '=' {
				v <<= 6
				continue
			}
			x, ok := rev[s[i+j]]
			if !ok {
				t.Fatalf("bad char %c", s[i+j])
			}
			v = v<<6 | uint32(x)
		}
		out = append(out, byte(v>>16), byte(v>>8), byte(v))
	}
	// Trim padding based on '=' count.
	pad := 0
	for i := len(s) - 1; i >= 0 && s[i] == '='; i-- {
		pad++
	}
	return out[:len(out)-pad]
}

func findReleaseID(ctx context.Context, t *testing.T, s *store.Store, policyID uuid.UUID) string {
	t.Helper()
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM release_transactions WHERE policy_id = $1 ORDER BY started_at DESC LIMIT 1`, policyID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// insertBundleWithID is a test-local copy so we can specify the ID explicitly
// (keeping the object-storage key and DB row in sync). The RETURNING scan is
// deliberate: it round-trips the full row through store.ContentBundle so a
// schema change the struct can't scan fails here, not in production reads.
func insertBundleWithID(ctx context.Context, q store.Querier, b *store.ContentBundle) error {
	var out store.ContentBundle
	return q.QueryRow(ctx,
		`INSERT INTO content_bundles
		   (id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		    primary_uri, backup_uri, size_bytes, ciphertext_sha256)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id, user_id, version, label, manifest_hash, manifest, wrapped_bundle_key, wrap_scheme,
		           primary_uri, backup_uri, size_bytes, ciphertext_sha256, created_at, deleted_at`,
		b.ID, b.UserID, b.Version, b.Label, b.ManifestHash, b.Manifest, b.WrappedBundleKey, b.WrapScheme,
		b.PrimaryURI, b.BackupURI, b.SizeBytes, b.CiphertextSHA256,
	).Scan(&out.ID, &out.UserID, &out.Version, &out.Label, &out.ManifestHash, &out.Manifest, &out.WrappedBundleKey, &out.WrapScheme,
		&out.PrimaryURI, &out.BackupURI, &out.SizeBytes, &out.CiphertextSHA256, &out.CreatedAt, &out.DeletedAt)
}
