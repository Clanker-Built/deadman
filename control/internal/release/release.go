// Package release is the post-trigger pipeline:
//
//   1. Detect policies in state 'triggered' with no active release transaction
//      at the current epoch → create one.
//   2. Unseal: fetch bundle ciphertext + wrapped key from object storage, use
//      the server release private key to recover the DEK, AEAD-decrypt the
//      payload. Happens entirely in the release worker's memory.
//   3. Package: write a landing page (HTML), the decrypted payload, a
//      manifest, SHA-256 checksums, and a detached Ed25519 signature to
//      primary object storage under a stable release slug.
//   4. Notify destinations: public_page returns the URL; webhook POSTs a
//      signed JSON with manifest hash + URL.
//   5. Advance the state machine: release_started → release_finished.
//
// Idempotency: keyed on (policy_id, epoch). If we crash mid-publish, the
// next tick resumes based on release_transactions.state.
package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/notify"
	"github.com/gcottrell/deadman/control/internal/policy"
	"github.com/gcottrell/deadman/control/internal/state"
	"github.com/gcottrell/deadman/control/internal/storage"
	"github.com/gcottrell/deadman/control/internal/store"
)

// KeyProvider returns the current RSA release private key, or nil if the
// keyvault is locked. The release worker calls this once per attempted
// release; if nil, the release is deferred until the operator unlocks.
type KeyProvider interface {
	PrivateKey() *rsa.PrivateKey
	Unlocked() bool
}

// MailResolver returns the current Sender, rebuilt from live config. nil
// result means SMTP is not configured. Returning a fresh value each call
// lets admin SMTP edits take effect without a process restart.
type MailResolver func(ctx context.Context) *notify.Sender

// Worker runs the release pipeline.
type Worker struct {
	Store         *store.Store
	Policy        *policy.Service
	Ledger        *audit.Ledger
	ReleaseKey    KeyProvider // threshold-protected key holder (keyvault.Locker in prod)
	ServiceSigner ed25519.PrivateKey
	ServicePub    ed25519.PublicKey
	Storage       *storage.DualWriter
	Primary       *storage.Client // public URL resolution uses the primary endpoint
	PublicBaseURL string          // e.g. https://releases.example.com/; if empty, the primary URI is exposed directly
	// Mail resolves the current mailer each delivery. nil disables email
	// destinations. The resolver lets admin SMTP-config changes take effect
	// without a restart.
	Mail MailResolver
	Logger        *slog.Logger
	HTTP          *http.Client
}

// New constructs a Worker with a sane HTTP client if one is not supplied.
func New(w Worker) *Worker {
	if w.HTTP == nil {
		w.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	return &w
}

// Tick is called periodically (from the scheduler). It (1) creates release
// transactions for newly-triggered policies and (2) advances any open ones.
//
// If the keyvault is locked, releases are not advanced — they stall in
// 'pending' / 'unsealing' state until the operator unlocks. Creation of
// release_transactions still happens so the audit trail is consistent.
func (w *Worker) Tick(ctx context.Context) error {
	if err := w.createMissing(ctx); err != nil {
		w.Logger.Warn("release: create missing", "err", err)
	}
	if w.ReleaseKey == nil || !w.ReleaseKey.Unlocked() {
		// Nothing we can do at release time without the private key.
		// Scheduler will retry; once unlocked, any pending transactions advance.
		return nil
	}
	return w.advancePending(ctx)
}

func (w *Worker) createMissing(ctx context.Context) error {
	rows, err := store.ListTriggeredPoliciesNeedingRelease(ctx, w.Store.Pool, 100)
	if err != nil {
		return err
	}
	for _, r := range rows {
		err := w.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
			_, _, err := store.CreateOrGetReleaseTransaction(ctx, q, r.PolicyID, r.PolicyVersionID, r.Epoch)
			if err != nil {
				return err
			}
			// Advance state machine to Releasing.
			return w.Policy.ReleaseStarted(ctx, r.PolicyID)
		})
		if err != nil {
			w.Logger.Warn("release: create tx", "policy_id", r.PolicyID, "err", err)
		}
	}
	return nil
}

func (w *Worker) advancePending(ctx context.Context) error {
	var txs []store.ReleaseTransaction
	err := w.Store.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		var e error
		txs, e = store.FindPendingReleases(ctx, q, 10)
		return e
	})
	if err != nil {
		return err
	}
	for _, rt := range txs {
		if err := w.runOne(ctx, rt); err != nil {
			w.Logger.Warn("release: run", "release_id", rt.ID, "err", err)
		}
	}
	return nil
}

// runOne executes the full pipeline for a single release transaction. Each
// phase is idempotent: re-running after a crash picks up from the last
// persisted state.
func (w *Worker) runOne(ctx context.Context, rt store.ReleaseTransaction) error {
	log := w.Logger.With("release_id", rt.ID, "policy_id", rt.PolicyID)
	log.Info("release: starting", "state", rt.State)

	// Load the policy version + its bundle/destination IDs.
	pv, err := store.GetActivePolicyVersion(ctx, w.Store.Pool, rt.PolicyID)
	if err != nil {
		return fmt.Errorf("load policy version: %w", err)
	}

	// Unseal all configured bundles into memory.
	_ = store.UpdateReleaseState(ctx, w.Store.Pool, rt.ID, "unsealing")
	payloads := make(map[uuid.UUID][]byte, len(pv.ContentBundleIDs))
	bundleMeta := make(map[uuid.UUID]store.ContentBundle, len(pv.ContentBundleIDs))
	for _, bid := range pv.ContentBundleIDs {
		b, err := store.GetBundle(ctx, w.Store.Pool, bid)
		if err != nil {
			return fmt.Errorf("load bundle %s: %w", bid, err)
		}
		pt, err := w.unseal(ctx, b)
		if err != nil {
			return fmt.Errorf("unseal bundle %s: %w", bid, err)
		}
		payloads[bid] = pt
		bundleMeta[bid] = *b
	}

	// Package.
	_ = store.UpdateReleaseState(ctx, w.Store.Pool, rt.ID, "packaging")
	slug := releaseSlug(rt.ID)
	manifest, landing, packagedErr := w.packageRelease(rt, *pv, payloads, bundleMeta, slug)
	if packagedErr != nil {
		return fmt.Errorf("package: %w", packagedErr)
	}

	// Publish.
	_ = store.UpdateReleaseState(ctx, w.Store.Pool, rt.ID, "publishing")
	publicURL, err := w.publish(ctx, slug, payloads, bundleMeta, manifest, landing)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// Deliver to destinations.
	allOK := true
	for _, did := range pv.DestinationIDs {
		d, err := store.GetDestination(ctx, w.Store.Pool, did)
		if err != nil || d.RevokedAt != nil {
			_ = store.RecordDestinationAttempt(ctx, w.Store.Pool, rt.ID, did, 1, "failed", "destination revoked or missing")
			allOK = false
			continue
		}
		if err := w.deliver(ctx, d, publicURL, manifest); err != nil {
			_ = store.RecordDestinationAttempt(ctx, w.Store.Pool, rt.ID, did, 1, "failed", err.Error())
			allOK = false
			continue
		}
		_ = store.RecordDestinationAttempt(ctx, w.Store.Pool, rt.ID, did, 1, "ok", "")
	}

	// Sign + finalize.
	manifestJSON, _ := json.Marshal(manifest)
	sig := ed25519.Sign(w.ServiceSigner, manifestJSON)
	finalState := "completed"
	if !allOK {
		finalState = "failed_partial"
	}
	if err := store.FinishRelease(ctx, w.Store.Pool, rt.ID, finalState, manifestJSON, sig); err != nil {
		return err
	}

	// Advance state machine.
	if err := w.Policy.ReleaseFinished(ctx, rt.PolicyID, allOK); err != nil {
		w.Logger.Warn("release: state finalize", "err", err)
	}

	// Audit.
	_, _ = w.Ledger.Append(ctx, w.Store, audit.Event{
		ActorKind:   audit.ActorService,
		EventType:   "release.completed",
		SubjectKind: "policy",
		SubjectID:   &rt.PolicyID,
		Payload: map[string]any{
			"release_id": rt.ID,
			"public_url": publicURL,
			"all_ok":     allOK,
			"manifest_hash": hex.EncodeToString(sha256BytesLen(manifestJSON)),
		},
	})
	log.Info("release: finished", "state", finalState, "public_url", publicURL)
	return nil
}

func (w *Worker) unseal(ctx context.Context, b *store.ContentBundle) ([]byte, error) {
	if b.WrapScheme != crypto.SchemeRSAOAEPAESGCM {
		return nil, fmt.Errorf("unsupported wrap scheme: %s", b.WrapScheme)
	}
	key := objectKey(b.PrimaryURI)
	// DualWriter.Get tries primary first, falls back to backup. Critical for
	// surviving a single-cloud outage while release is in-flight (§29.3).
	body, source, err := w.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	ct, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	// Audit which side served the read so post-mortems can see when backup
	// saved us. Non-fatal on failure — the release itself is more important.
	_, _ = w.Ledger.Append(ctx, w.Store, audit.Event{
		ActorKind:   audit.ActorService,
		EventType:   "release.unseal_source",
		SubjectKind: "bundle",
		SubjectID:   &b.ID,
		Payload:     map[string]any{"source": source},
	})
	priv := w.ReleaseKey.PrivateKey()
	if priv == nil {
		return nil, fmt.Errorf("keyvault locked; cannot unseal")
	}
	return crypto.DecryptBundleForRelease(priv, ct, b.WrappedBundleKey, b.ManifestHash)
}

func objectKey(uri string) string {
	rest := strings.TrimPrefix(uri, "s3://")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[i+1:]
	}
	return rest
}

type manifestT struct {
	ReleaseID      uuid.UUID         `json:"release_id"`
	PolicyID       uuid.UUID         `json:"policy_id"`
	VersionID      uuid.UUID         `json:"version_id"`
	Epoch          int64             `json:"epoch"`
	ReleasedAt     time.Time         `json:"released_at"`
	ReleaseMode    string            `json:"release_mode"`
	Bundles        []manifestBundle  `json:"bundles"`
	ServicePubKey  string            `json:"service_pubkey_b64"` // base64-raw-url
}

type manifestBundle struct {
	ID        uuid.UUID `json:"id"`
	Label     string    `json:"label,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256_hex"`
	Filename  string    `json:"filename"`
}

func (w *Worker) packageRelease(rt store.ReleaseTransaction, pv store.PolicyVersion, payloads map[uuid.UUID][]byte, meta map[uuid.UUID]store.ContentBundle, slug string) (manifestT, []byte, error) {
	m := manifestT{
		ReleaseID:     rt.ID,
		PolicyID:      rt.PolicyID,
		VersionID:     pv.ID,
		Epoch:         rt.Epoch,
		ReleasedAt:    time.Now().UTC().Truncate(time.Second),
		ReleaseMode:   pv.ReleaseMode,
		ServicePubKey: base64URLNoPad(w.ServicePub),
	}
	for bid, payload := range payloads {
		h := sha256.Sum256(payload)
		m.Bundles = append(m.Bundles, manifestBundle{
			ID:        bid,
			Label:     meta[bid].Label,
			SizeBytes: int64(len(payload)),
			SHA256:    hex.EncodeToString(h[:]),
			Filename:  bid.String() + ".bin",
		})
	}
	landing := renderLanding(slug, m)
	return m, landing, nil
}

func (w *Worker) publish(ctx context.Context, slug string, payloads map[uuid.UUID][]byte, meta map[uuid.UUID]store.ContentBundle, m manifestT, landing []byte) (string, error) {
	base := "releases/" + slug + "/"
	// Landing HTML.
	if _, err := w.Storage.Put(ctx, base+"index.html", landing, "text/html; charset=utf-8"); err != nil {
		return "", err
	}
	// Manifest + signature.
	mj, _ := json.MarshalIndent(m, "", "  ")
	if _, err := w.Storage.Put(ctx, base+"manifest.json", mj, "application/json"); err != nil {
		return "", err
	}
	mSig := ed25519.Sign(w.ServiceSigner, mj)
	if _, err := w.Storage.Put(ctx, base+"manifest.sig", mSig, "application/octet-stream"); err != nil {
		return "", err
	}
	// Bundles.
	for bid, payload := range payloads {
		_ = meta
		if _, err := w.Storage.Put(ctx, base+bid.String()+".bin", payload, "application/octet-stream"); err != nil {
			return "", err
		}
	}
	if w.PublicBaseURL != "" {
		u := strings.TrimRight(w.PublicBaseURL, "/") + "/" + slug + "/"
		return u, nil
	}
	// Fallback: return the s3 URI so the UI can at least render *something*.
	return w.Primary.URI(base + "index.html"), nil
}

func (w *Worker) deliver(ctx context.Context, d *store.Destination, publicURL string, m manifestT) error {
	switch d.Kind {
	case "public_page":
		// Nothing to deliver — the landing page is the delivery. Record OK.
		return nil
	case "email":
		var sender *notify.Sender
		if w.Mail != nil {
			sender = w.Mail(ctx)
		}
		if sender == nil {
			return fmt.Errorf("email destination but SMTP not configured")
		}
		var cfg struct {
			Recipients []string `json:"recipients"`
			Subject    string   `json:"subject"`
		}
		if err := json.Unmarshal(d.Config, &cfg); err != nil {
			return fmt.Errorf("email config: %w", err)
		}
		if len(cfg.Recipients) == 0 {
			return fmt.Errorf("email destination has no recipients")
		}
		subject := cfg.Subject
		if subject == "" {
			subject = "Deadman release"
		}
		body := fmt.Sprintf(
			"A deadman's switch release has been triggered.\n\n"+
				"Release ID: %s\nPolicy ID: %s\nReleased at: %s\n\n"+
				"Access the release:\n  %s\n\n"+
				"A signed manifest is published alongside the archive. Verify it\n"+
				"with the service public key below (base64url):\n\n  %s\n",
			m.ReleaseID, m.PolicyID, m.ReleasedAt.Format("2006-01-02 15:04:05 UTC"),
			publicURL, m.ServicePubKey,
		)
		return sender.Send(cfg.Recipients, subject, body)
	case "webhook":
		var cfg struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(d.Config, &cfg); err != nil {
			return fmt.Errorf("webhook config: %w", err)
		}
		if _, err := url.Parse(cfg.URL); err != nil || cfg.URL == "" {
			return fmt.Errorf("webhook url invalid")
		}
		body, _ := json.Marshal(map[string]any{
			"release_id": m.ReleaseID,
			"policy_id":  m.PolicyID,
			"public_url": publicURL,
			"manifest":   m,
		})
		sig := ed25519.Sign(w.ServiceSigner, body)
		reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Deadman-Signature", base64URLNoPad(sig))
		req.Header.Set("X-Deadman-Service-PubKey", base64URLNoPad(w.ServicePub))
		resp, err := w.HTTP.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("webhook status %d", resp.StatusCode)
		}
		return nil
	default:
		return fmt.Errorf("unsupported destination kind: %s", d.Kind)
	}
}

func releaseSlug(id uuid.UUID) string {
	// Opaque unguessable slug = release id (UUIDv4, 122 bits of randomness).
	return id.String()
}

func sha256BytesLen(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func base64URLNoPad(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(b) == 0 {
		return ""
	}
	var out []byte
	i := 0
	for ; i+3 <= len(b); i += 3 {
		v := uint(b[i])<<16 | uint(b[i+1])<<8 | uint(b[i+2])
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f], alphabet[(v>>6)&0x3f], alphabet[v&0x3f])
	}
	switch len(b) - i {
	case 1:
		v := uint(b[i]) << 16
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f])
	case 2:
		v := uint(b[i])<<16 | uint(b[i+1])<<8
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f], alphabet[(v>>6)&0x3f])
	}
	return string(out)
}

// EventReleaseStarted is exposed so the policy package can import it cleanly.
var _ = state.EventReleaseStarted
