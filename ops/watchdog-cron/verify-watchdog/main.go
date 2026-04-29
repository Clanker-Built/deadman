// verify-watchdog reads a Deadman /watchdog JSON response on stdin, verifies
// the Ed25519 signature against a pinned public key, and exits 0 iff the
// signature is valid AND last_scheduler_tick is fresher than the configured
// staleness threshold.
//
// The tool is deliberately small and dependency-free so it can be deployed
// on any cheap watchdog VPS without dragging the Deadman control-plane
// codebase along.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type watchdogResp struct {
	ServicePubkey      string `json:"service_pubkey"`
	LastSchedulerTick  string `json:"last_scheduler_tick"`
	Now                string `json:"now"`
	Signature          string `json:"signature"`
}

func main() {
	pubkeyB64 := flag.String("pubkey", "", "base64url-unpadded service public key (REQUIRED)")
	maxStale := flag.Int("max-stale-seconds", 300, "fail if (now - last_scheduler_tick) exceeds this")
	flag.Parse()
	if *pubkeyB64 == "" {
		fail("--pubkey is required")
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(*pubkeyB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		fail("--pubkey must be base64url-unpadded ed25519 public key")
	}
	pinnedPub := ed25519.PublicKey(pubBytes)

	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}
	var r watchdogResp
	if err := json.Unmarshal(body, &r); err != nil {
		fail("decode JSON: %v", err)
	}

	// Cross-check: server's reported pubkey must match the pinned one.
	srvPub, err := base64.RawURLEncoding.DecodeString(r.ServicePubkey)
	if err != nil || len(srvPub) != ed25519.PublicKeySize {
		fail("server pubkey wrong size or encoding")
	}
	if string(srvPub) != string(pinnedPub) {
		fail("server pubkey does not match pinned key — IMPERSONATION")
	}

	// Canonical signing input: "tick=<RFC3339>|now=<RFC3339>".
	sigBody := []byte("tick=" + r.LastSchedulerTick + "|now=" + r.Now)
	sig, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil {
		fail("decode signature: %v", err)
	}
	if !ed25519.Verify(pinnedPub, sigBody, sig) {
		fail("ed25519 signature invalid")
	}

	tick, err := time.Parse(time.RFC3339, r.LastSchedulerTick)
	if err != nil {
		fail("parse last_scheduler_tick: %v", err)
	}
	now, err := time.Parse(time.RFC3339, r.Now)
	if err != nil {
		fail("parse now: %v", err)
	}
	staleness := now.Sub(tick)
	if staleness > time.Duration(*maxStale)*time.Second {
		fail("scheduler is STALE: last tick %s, now %s, gap %s (threshold %ds)",
			tick.Format(time.RFC3339), now.Format(time.RFC3339), staleness, *maxStale)
	}
	fmt.Fprintln(os.Stderr, "watchdog OK")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify-watchdog: "+format+"\n", args...)
	os.Exit(1)
}
