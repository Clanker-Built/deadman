package release_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/release"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// TestRestoreDrillPrimaryOutage: simulates a primary-storage outage between
// upload and release. Release must still complete by reading the backup copy.
// This is the §29.3 resilience guarantee.
func TestRestoreDrillPrimaryOutage(t *testing.T) {
	dbURL := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DEADMAN_DATABASE_URL")
	}
	minioURL := os.Getenv("DEADMAN_S3_PRIMARY_ENDPOINT")
	backupURL := os.Getenv("DEADMAN_S3_BACKUP_ENDPOINT")
	s3Key := os.Getenv("DEADMAN_S3_ACCESS_KEY")
	s3Secret := os.Getenv("DEADMAN_S3_SECRET_KEY")
	if dbURL == "" || minioURL == "" || backupURL == "" || s3Key == "" {
		t.Skip("need DB + both MinIO endpoints")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	bucket := "drill-" + uuid.NewString()[:8]
	primary, err := storage.New(ctx, storage.Config{
		Endpoint: minioURL, Region: "us-east-1", Bucket: bucket,
		AccessKeyID: s3Key, SecretAccessKey: s3Secret, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	backup, err := storage.New(ctx, storage.Config{
		Endpoint: backupURL, Region: "us-east-1", Bucket: bucket,
		AccessKeyID: s3Key, SecretAccessKey: s3Secret, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	dw := &storage.DualWriter{Primary: primary, Backup: backup}

	relKey, err := crypto.LoadOrCreateReleaseKey(filepath.Join(t.TempDir(), "rel.pem"))
	if err != nil {
		t.Fatal(err)
	}
	servicePub, servicePriv, _ := ed25519.GenerateKey(rand.Reader)
	ledger := audit.NewLedger(servicePriv)

	clk := &fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	polSvc := policy.New(s, ledger, clk)

	// Seed user + bundle (dual-written).
	email := "drill-" + uuid.NewString() + "@test.local"
	var userID uuid.UUID
	_ = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, _ := store.CreateUser(ctx, q, email, "Drill", nil)
		userID = u.ID
		return nil
	})
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	plaintext := []byte("evidence that must survive primary outage")
	manifest := []byte(`{"label":"drill","file_count":1}`)
	mh := crypto.SHA256(manifest)
	ct, wrapped, _ := crypto.EncryptBundleForRelease(&relKey.PublicKey, plaintext, mh[:])

	bundleID := uuid.New()
	objKey := "bundles/" + userID.String() + "/" + bundleID.String() + ".bin"
	wr, err := dw.Put(ctx, objKey, ct, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if wr.BackupURI == "" {
		t.Fatal("backup write didn't complete; drill cannot validate fallback")
	}

	var destID uuid.UUID
	_ = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		b := &store.ContentBundle{
			ID: bundleID, UserID: userID, Version: 1, Label: "drill",
			ManifestHash: mh[:], Manifest: manifest,
			WrappedBundleKey: wrapped, WrapScheme: crypto.SchemeRSAOAEPAESGCM,
			PrimaryURI: wr.PrimaryURI, BackupURI: &wr.BackupURI,
			SizeBytes: int64(len(ct)),
			CiphertextSHA256: (func() []byte { h := crypto.SHA256(ct); return h[:] })(),
		}
		_, e := insertBundleWithID(ctx, q, b)
		if e != nil {
			return e
		}
		backupURIStr := wr.BackupURI
		_ = backupURIStr
		cfg, _ := json.Marshal(map[string]string{})
		d, e := store.CreateDestination(ctx, q, &store.Destination{
			UserID: userID, Kind: "public_page", Label: "drill page", Config: cfg,
		})
		if e != nil {
			return e
		}
		destID = d.ID
		return nil
	})

	p, _, err := polSvc.Create(ctx, policy.CreateInput{
		UserID: userID, Title: "drill",
		IntervalDays: 14, GracePeriodHours: 72,
		ReleaseMode:    "limited_public",
		DestinationIDs: []uuid.UUID{destID}, BundleIDs: []uuid.UUID{bundleID},
		UserSignature: make([]byte, ed25519.SignatureSize),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := polSvc.Arm(ctx, userID, p.ID); err != nil {
		t.Fatal(err)
	}

	// Simulate primary outage: delete the ciphertext from primary bucket.
	// Backup still has it. Verifier/release must read from backup.
	if _, err := primary.RawS3().DeleteObject(ctx, &s3sdk.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(objKey),
	}); err != nil {
		t.Fatalf("simulate outage: %v", err)
	}

	// Run the lifecycle through to triggered.
	for _, d := range []time.Duration{
		14*24*time.Hour - 23*time.Hour,
		24 * time.Hour,
		73 * time.Hour,
	} {
		clk.Advance(d)
		if _, err := polSvc.Tick(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}

	// Run release worker.
	w := release.New(release.Worker{
		Store: s, Policy: polSvc, Ledger: ledger,
		ReleaseKey: &release.StaticKey{K: relKey}, ServiceSigner: servicePriv, ServicePub: servicePub,
		Storage: dw, Primary: primary,
	})
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}

	// State must be released — the backup served the read.
	pg, _ := store.GetPolicy(ctx, s.Pool, p.ID)
	if pg.State != "released" {
		t.Fatalf("want released after primary-outage drill, got %s", pg.State)
	}

	// And the landing page was written (to primary, which is now back — but
	// we deleted only the bundle object, not the whole bucket, so publish
	// succeeded). We assert the published payload matches original.
	var releaseID string
	_ = s.Pool.QueryRow(ctx,
		`SELECT id FROM release_transactions WHERE policy_id = $1 LIMIT 1`, p.ID,
	).Scan(&releaseID)
	rc, err := primary.Get(ctx, "releases/"+releaseID+"/"+bundleID.String()+".bin")
	if err != nil {
		t.Fatalf("fetch published bundle: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != string(plaintext) {
		t.Fatal("published bundle does not match original plaintext")
	}

	// Confirm the audit trail recorded that backup served the unseal read.
	var sourceCount int
	_ = s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		 WHERE event_type = 'release.unseal_source'
		   AND payload->>'source' = 'backup'
		   AND subject_id = $1`, bundleID,
	).Scan(&sourceCount)
	if sourceCount == 0 {
		t.Fatal("no audit event confirming backup served the unseal read")
	}
}
