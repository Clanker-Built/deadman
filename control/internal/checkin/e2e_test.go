package checkin_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/auth"
	"github.com/gcottrell/deadman/control/internal/checkin"
	"github.com/gcottrell/deadman/control/internal/httpapi"
	"github.com/gcottrell/deadman/control/internal/store"
)

// TestCheckinFullFlow exercises device enrollment → nonce issuance →
// signed-nonce verification against the real HTTP surface and DB. It bypasses
// WebAuthn (which needs a real browser authenticator) by minting a session
// directly; the device crypto path is the one under test.
func TestCheckinFullFlow(t *testing.T) {
	url := os.Getenv("DEADMAN_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DEADMAN_DATABASE_URL")
	}
	if url == "" {
		t.Skip("no DB url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := store.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.NewLedger(priv)

	authSvc, err := auth.NewService(auth.Config{
		RPDisplayName: "Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	}, s, ledger)
	if err != nil {
		t.Fatal(err)
	}

	ns := checkin.NewStore()
	handler := httpapi.NewRouterWithDeps(httpapi.Deps{
		Logger: slog.Default(),
		Store:  s,
		Auth:   authSvc,
		Ledger: ledger,
		Nonces: ns,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// Seed a user and a session directly (bypass passkey).
	email := "checkin-" + uuid.NewString() + "@test.local"
	var userID uuid.UUID
	err = s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		u, e := store.CreateUser(ctx, q, email, "Checkin User", nil)
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

	token, _, err := authSvc.IssueSession(ctx, userID, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := auth.SessionCookieName + "=" + token

	// Device keypair — simulates StrongBox / Secure Enclave key.
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)

	// 1. Enroll device.
	enrollBody, _ := json.Marshal(map[string]string{
		"platform":      "android",
		"nickname":      "pixel-test",
		"device_pubkey": base64.RawURLEncoding.EncodeToString(devPub),
	})
	resp := doReal(t, server.URL+"/api/v1/devices/", cookie, enrollBody)
	defer resp.Close()
	if resp.Status() != 201 {
		t.Fatalf("enroll: status %d body=%s", resp.Status(), resp.Body())
	}
	var enrollResp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(resp.Body()), &enrollResp)
	deviceID := enrollResp.ID
	if deviceID == "" {
		t.Fatal("no device id in enroll response")
	}

	// 2. Request a nonce.
	nonceReq, _ := json.Marshal(map[string]string{"device_id": deviceID})
	nResp := doReal(t, server.URL+"/api/v1/checkin/nonce", cookie, nonceReq)
	defer nResp.Close()
	if nResp.Status() != 200 {
		t.Fatalf("nonce: status %d body=%s", nResp.Status(), nResp.Body())
	}
	var nonceResp struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(nResp.Body()), &nonceResp)
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceResp.Nonce)
	if len(nonce) != checkin.NonceSize {
		t.Fatalf("bad nonce len %d", len(nonce))
	}

	// 3. Sign and verify.
	var n32 [checkin.NonceSize]byte
	copy(n32[:], nonce)
	counter := int64(1)
	digest := checkin.Payload(n32, counter)
	sig := ed25519.Sign(devPriv, digest[:])

	verifyBody, _ := json.Marshal(map[string]any{
		"device_id": deviceID,
		"nonce":     nonceResp.Nonce,
		"counter":   counter,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})

	// Freshly enrolled: still inside the 24h delayed-trust window, so the
	// verify must be rejected even though the signature is valid.
	dResp := doReal(t, server.URL+"/api/v1/checkin/verify", cookie, verifyBody)
	defer dResp.Close()
	if dResp.Status() != http.StatusForbidden {
		t.Fatalf("delayed-trust: want 403, got %d body=%s", dResp.Status(), dResp.Body())
	}

	// Backdate the trust window; the same (unconsumed) nonce then verifies.
	if _, err := s.Pool.Exec(ctx, `UPDATE devices SET trusted_after = now() - interval '1 hour' WHERE id = $1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	vResp := doReal(t, server.URL+"/api/v1/checkin/verify", cookie, verifyBody)
	defer vResp.Close()
	if vResp.Status() != 200 {
		t.Fatalf("verify: status %d body=%s", vResp.Status(), vResp.Body())
	}

	// 4. Verify DB state: device counter bumped, audit event present.
	var got int64
	_ = s.Pool.QueryRow(ctx, `SELECT monotonic_counter FROM devices WHERE id = $1::uuid`, deviceID).Scan(&got)
	if got != 1 {
		t.Fatalf("counter not bumped: %d", got)
	}
	var count int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='checkin.verified'`).Scan(&count)
	if count == 0 {
		t.Fatal("no checkin.verified audit event written")
	}

	// 5. Replay the same nonce — must be rejected.
	rResp := doReal(t, server.URL+"/api/v1/checkin/verify", cookie, verifyBody)
	defer rResp.Close()
	if rResp.Status() == 200 {
		t.Fatalf("replay accepted: body=%s", rResp.Body())
	}

}

// doResp wraps a testing http call for readability.
type doResp struct {
	status int
	body   string
	closer func()
}

func (r *doResp) Status() int  { return r.status }
func (r *doResp) Body() string { return r.body }
func (r *doResp) Close()       { r.closer() }

func doReal(t *testing.T, url, cookie string, body []byte) *doResp {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &doResp{status: resp.StatusCode, body: string(b), closer: func() {}}
}
