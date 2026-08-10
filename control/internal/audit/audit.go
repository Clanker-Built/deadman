// Package audit is the tamper-evident append-only event log.
//
// Every event is hash-chained: payload_hash = SHA256(canonical(event)); each
// row stores prev_hash = the previous row's payload_hash. The first row's
// prev_hash is 32 zero bytes. The service additionally signs (prev_hash ||
// payload_hash) with its Ed25519 signing key, giving two independent verify
// paths: the chain (detects rewrites) and the signature (detects forgery).
//
// The DB layer enforces append-only via a trigger. Even a DBA doing UPDATE
// or DELETE will hit the raise-exception trigger.
package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/gcottrell/deadman/control/internal/crypto"
	"github.com/gcottrell/deadman/control/internal/store"
)

// ActorKind matches the DB CHECK constraint.
type ActorKind string

const (
	ActorUser     ActorKind = "user"
	ActorDevice   ActorKind = "device"
	ActorService  ActorKind = "service"
	ActorSystem   ActorKind = "system"
	ActorDelegate ActorKind = "delegate"
)

// Event is the logical audit record callers construct. The ledger computes
// hashes and signatures; callers never set them.
type Event struct {
	ActorKind   ActorKind      `json:"actor_kind"`
	ActorID     *uuid.UUID     `json:"actor_id,omitempty"`
	EventType   string         `json:"event_type"`
	SubjectKind string         `json:"subject_kind,omitempty"`
	SubjectID   *uuid.UUID     `json:"subject_id,omitempty"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// Record is a persisted event returned by reads.
type Record struct {
	Seq              int64
	ID               uuid.UUID
	OccurredAt       time.Time
	ActorKind        ActorKind
	ActorID          *uuid.UUID
	EventType        string
	SubjectKind      *string
	SubjectID        *uuid.UUID
	Payload          json.RawMessage
	PrevHash         [32]byte
	PayloadHash      [32]byte
	ServiceSignature []byte
}

// Ledger appends events. Construct once at process start with the service
// Ed25519 signing key.
type Ledger struct {
	signingKey ed25519.PrivateKey
}

// NewLedger returns a Ledger that signs events with the given service key.
func NewLedger(key ed25519.PrivateKey) *Ledger {
	if len(key) != ed25519.PrivateKeySize {
		panic("audit: service signing key has wrong size")
	}
	return &Ledger{signingKey: key}
}

// Append writes a single event inside a transaction so the hash chain cannot
// interleave with concurrent writers. Appenders are serialized by a
// transaction-scoped advisory lock (see appendTx).
func (l *Ledger) Append(ctx context.Context, s *store.Store, e Event) (*Record, error) {
	if e.EventType == "" {
		return nil, errors.New("audit: event_type required")
	}
	var rec *Record
	err := s.InTx(ctx, func(ctx context.Context, q store.Querier) error {
		r, err := l.appendTx(ctx, q, e)
		if err != nil {
			return err
		}
		rec = r
		return nil
	})
	return rec, err
}

// AppendTx appends inside an existing transaction. Use when the audit event
// must be atomic with a business-table write (e.g. user creation).
func (l *Ledger) AppendTx(ctx context.Context, q store.Querier, e Event) (*Record, error) {
	return l.appendTx(ctx, q, e)
}

// auditChainLockKey is the pg_advisory_xact_lock key that serializes audit
// appenders. Arbitrary fixed value ("auditcha" in ASCII); it must simply be
// unique among advisory-lock keys used against this database (none others
// exist today).
const auditChainLockKey int64 = 0x6175646974636861

func (l *Ledger) appendTx(ctx context.Context, q store.Querier, e Event) (*Record, error) {
	// Serialize appenders for the rest of the transaction. FOR UPDATE on the
	// tip row is not enough: under READ COMMITTED a blocked appender re-checks
	// only the row it locked and never re-scans for the winner's newly
	// committed tip, so both would read the same prev_hash and fork the
	// chain. The advisory lock is released automatically at commit/rollback.
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return nil, fmt.Errorf("audit: acquire chain lock: %w", err)
	}
	// Read the chain tip. If no rows yet, seq 1 is the first.
	var prevHash [32]byte
	var prevBytes []byte
	err := q.QueryRow(ctx,
		`SELECT payload_hash FROM audit_events ORDER BY seq DESC LIMIT 1`,
	).Scan(&prevBytes)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("audit: read tip: %w", err)
	}
	if len(prevBytes) == 32 {
		copy(prevHash[:], prevBytes)
	} else if len(prevBytes) != 0 {
		return nil, fmt.Errorf("audit: tip hash wrong size: %d", len(prevBytes))
	}

	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal payload: %w", err)
	}
	// Hash the canonical payload form, not the raw insert bytes. The payload
	// column is JSONB: Postgres rewrites key order, whitespace, and number
	// formatting on storage, so Verify can only recompute the hash from a
	// form both sides can derive (see canonicalPayload). payloadJSON itself
	// is still what gets stored.
	hashPayload, err := canonicalPayload(payloadJSON)
	if err != nil {
		return nil, fmt.Errorf("audit: canonicalize payload: %w", err)
	}

	// Truncate to microseconds — Postgres TIMESTAMPTZ stores µs precision,
	// so the post-roundtrip value must match the pre-insert hash input.
	occurredAt := time.Now().UTC().Truncate(time.Microsecond)
	eventID := uuid.New()

	// Canonical serialization. Field order matters and is fixed here.
	canon := canonicalize(canonicalEvent{
		ID:          eventID,
		OccurredAt:  occurredAt,
		ActorKind:   string(e.ActorKind),
		ActorID:     e.ActorID,
		EventType:   e.EventType,
		SubjectKind: e.SubjectKind,
		SubjectID:   e.SubjectID,
		Payload:     hashPayload,
		PrevHash:    prevHash[:],
	})
	payloadHash := crypto.SHA256(canon)

	sigBody := make([]byte, 0, 64)
	sigBody = append(sigBody, prevHash[:]...)
	sigBody = append(sigBody, payloadHash[:]...)
	sig := ed25519.Sign(l.signingKey, sigBody)

	var rec Record
	var prevRow, payloadRow []byte
	var actorKindStr string
	err = q.QueryRow(ctx,
		`INSERT INTO audit_events
		   (id, occurred_at, actor_kind, actor_id, event_type, subject_kind, subject_id,
		    payload, prev_hash, payload_hash, service_signature)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING seq, id, occurred_at, actor_kind, actor_id, event_type,
		   subject_kind, subject_id, payload, prev_hash, payload_hash, service_signature`,
		eventID, occurredAt, string(e.ActorKind), e.ActorID, e.EventType,
		nullString(e.SubjectKind), e.SubjectID, payloadJSON,
		prevHash[:], payloadHash[:], sig,
	).Scan(&rec.Seq, &rec.ID, &rec.OccurredAt, &actorKindStr, &rec.ActorID, &rec.EventType,
		&rec.SubjectKind, &rec.SubjectID, &rec.Payload, &prevRow, &payloadRow, &rec.ServiceSignature)
	if err != nil {
		return nil, fmt.Errorf("audit: insert: %w", err)
	}
	rec.ActorKind = ActorKind(actorKindStr)
	copy(rec.PrevHash[:], prevRow)
	copy(rec.PayloadHash[:], payloadRow)
	return &rec, nil
}

// ListForUser returns audit events where the given user is the actor or
// where the subject is one of that user's owned entities. The query relies
// on joins against policies/bundles/devices/destinations so users can see
// their own history without being able to read other users' events.
func ListForUser(ctx context.Context, q store.Querier, userID uuid.UUID, limit int) ([]Record, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		WITH owned AS (
		  SELECT id::uuid AS subject_id, 'policy' AS kind FROM policies WHERE user_id = $1
		  UNION ALL
		  SELECT id::uuid, 'bundle'   FROM content_bundles WHERE user_id = $1
		  UNION ALL
		  SELECT id::uuid, 'device'   FROM devices WHERE user_id = $1
		  UNION ALL
		  SELECT id::uuid, 'destination' FROM destinations WHERE user_id = $1
		  UNION ALL
		  SELECT $1::uuid, 'user'
		)
		SELECT ae.seq, ae.id, ae.occurred_at, ae.actor_kind, ae.actor_id,
		       ae.event_type, ae.subject_kind, ae.subject_id, ae.payload,
		       ae.prev_hash, ae.payload_hash, ae.service_signature
		FROM audit_events ae
		WHERE ae.actor_id = $1
		   OR EXISTS (
		     SELECT 1 FROM owned o
		     WHERE o.subject_id = ae.subject_id
		       AND o.kind = ae.subject_kind
		   )
		ORDER BY ae.seq DESC
		LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var actorKindStr string
		var prevRow, payloadRow []byte
		if err := rows.Scan(&r.Seq, &r.ID, &r.OccurredAt, &actorKindStr, &r.ActorID, &r.EventType,
			&r.SubjectKind, &r.SubjectID, &r.Payload, &prevRow, &payloadRow, &r.ServiceSignature); err != nil {
			return nil, err
		}
		r.ActorKind = ActorKind(actorKindStr)
		copy(r.PrevHash[:], prevRow)
		copy(r.PayloadHash[:], payloadRow)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AdminFilter filters a ListAll query. Zero values are ignored.
type AdminFilter struct {
	EventType string     // exact match
	ActorKind string     // exact match
	ActorID   *uuid.UUID // exact match
	Since     *time.Time // inclusive lower bound on occurred_at
	Until     *time.Time // exclusive upper bound on occurred_at
}

// ListAll is the admin-only cross-user audit read. Filters are optional.
// Ordered newest-first, bounded by limit.
func ListAll(ctx context.Context, q store.Querier, f AdminFilter, limit int) ([]Record, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	// Dynamic WHERE via parameterized args.
	args := []any{}
	clauses := []string{}
	add := func(clause string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.ActorKind != "" {
		add("actor_kind = $%d", f.ActorKind)
	}
	if f.ActorID != nil {
		add("actor_id = $%d", *f.ActorID)
	}
	if f.Since != nil {
		add("occurred_at >= $%d", f.Since.UTC())
	}
	if f.Until != nil {
		add("occurred_at < $%d", f.Until.UTC())
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT seq, id, occurred_at, actor_kind, actor_id, event_type,
		       subject_kind, subject_id, payload, prev_hash, payload_hash,
		       service_signature
		FROM audit_events %s
		ORDER BY seq DESC
		LIMIT $%d`, where, len(args))
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var actorKindStr string
		var prevRow, payloadRow []byte
		if err := rows.Scan(&r.Seq, &r.ID, &r.OccurredAt, &actorKindStr, &r.ActorID, &r.EventType,
			&r.SubjectKind, &r.SubjectID, &r.Payload, &prevRow, &payloadRow, &r.ServiceSignature); err != nil {
			return nil, err
		}
		r.ActorKind = ActorKind(actorKindStr)
		copy(r.PrevHash[:], prevRow)
		copy(r.PayloadHash[:], payloadRow)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Verify walks the chain in order and confirms every row's hash links to the
// previous and every signature validates. Stops at first break.
//
// Intended for nightly audit-integrity jobs and external-verifier tools.
func Verify(ctx context.Context, q store.Querier, servicePub ed25519.PublicKey) error {
	rows, err := q.Query(ctx,
		`SELECT seq, id, occurred_at, actor_kind, actor_id, event_type,
		        subject_kind, subject_id, payload, prev_hash, payload_hash, service_signature
		 FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var expectedPrev [32]byte
	for rows.Next() {
		var r Record
		var actorKindStr string
		var prevRow, payloadRow []byte
		if err := rows.Scan(&r.Seq, &r.ID, &r.OccurredAt, &actorKindStr, &r.ActorID, &r.EventType,
			&r.SubjectKind, &r.SubjectID, &r.Payload, &prevRow, &payloadRow, &r.ServiceSignature); err != nil {
			return err
		}
		r.ActorKind = ActorKind(actorKindStr)
		copy(r.PrevHash[:], prevRow)
		copy(r.PayloadHash[:], payloadRow)
		if r.PrevHash != expectedPrev {
			return fmt.Errorf("audit: chain break at seq=%d (prev_hash=%s, expected=%s)",
				r.Seq, hex.EncodeToString(r.PrevHash[:]), hex.EncodeToString(expectedPrev[:]))
		}
		var subjectKind string
		if r.SubjectKind != nil {
			subjectKind = *r.SubjectKind
		}
		// The JSONB column normalized the payload bytes hashed at insert (key
		// order, spacing, number formatting), so recompute the same canonical
		// form instead of hashing the stored bytes directly.
		canonPayload, err := canonicalPayload(r.Payload)
		if err != nil {
			return fmt.Errorf("audit: canonicalize payload at seq=%d: %w", r.Seq, err)
		}
		canon := canonicalize(canonicalEvent{
			ID:          r.ID,
			OccurredAt:  r.OccurredAt.UTC(),
			ActorKind:   string(r.ActorKind),
			ActorID:     r.ActorID,
			EventType:   r.EventType,
			SubjectKind: subjectKind,
			SubjectID:   r.SubjectID,
			Payload:     canonPayload,
			PrevHash:    r.PrevHash[:],
		})
		expectHash := crypto.SHA256(canon)
		if expectHash != r.PayloadHash {
			return fmt.Errorf("audit: payload hash mismatch at seq=%d", r.Seq)
		}
		sigBody := make([]byte, 0, 64)
		sigBody = append(sigBody, r.PrevHash[:]...)
		sigBody = append(sigBody, r.PayloadHash[:]...)
		if !ed25519.Verify(servicePub, sigBody, r.ServiceSignature) {
			return fmt.Errorf("audit: signature invalid at seq=%d", r.Seq)
		}
		expectedPrev = r.PayloadHash
	}
	return rows.Err()
}

// Head pins a point on the audit chain: a row's seq and payload_hash.
// Callers capture it via CurrentHead after trusted writes and later pass it
// to VerifyWithHead. Plain Verify cannot see tail truncation — a chain cut
// back to any earlier row (or to zero rows) still verifies as an intact,
// shorter chain — so external verifiers should pin a head.
type Head struct {
	Seq  int64
	Hash [32]byte
}

// CurrentHead returns the chain tip, or (nil, nil) when the ledger is empty.
func CurrentHead(ctx context.Context, q store.Querier) (*Head, error) {
	var h Head
	var hb []byte
	err := q.QueryRow(ctx,
		`SELECT seq, payload_hash FROM audit_events ORDER BY seq DESC LIMIT 1`,
	).Scan(&h.Seq, &hb)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: read head: %w", err)
	}
	if len(hb) != 32 {
		return nil, fmt.Errorf("audit: head hash wrong size: %d", len(hb))
	}
	copy(h.Hash[:], hb)
	return &h, nil
}

// VerifyWithHead runs Verify and additionally confirms the pinned head is
// still on the chain: the row at expected.Seq must exist and carry the
// pinned hash. Appends after the pin are fine — the pin anchors the prefix
// up to it — but truncation or rewrite at or before the pin is reported,
// including truncation to zero rows, which plain Verify accepts.
func VerifyWithHead(ctx context.Context, q store.Querier, servicePub ed25519.PublicKey, expected Head) error {
	if err := Verify(ctx, q, servicePub); err != nil {
		return err
	}
	var hb []byte
	err := q.QueryRow(ctx,
		`SELECT payload_hash FROM audit_events WHERE seq = $1`, expected.Seq,
	).Scan(&hb)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit: pinned head seq=%d missing — tail truncated", expected.Seq)
	}
	if err != nil {
		return fmt.Errorf("audit: read pinned head: %w", err)
	}
	var got [32]byte
	copy(got[:], hb)
	if len(hb) != 32 || got != expected.Hash {
		return fmt.Errorf("audit: pinned head hash mismatch at seq=%d (have %s, pinned %s)",
			expected.Seq, hex.EncodeToString(hb), hex.EncodeToString(expected.Hash[:]))
	}
	return nil
}

// canonicalEvent is the field order the canonical serializer commits to.
type canonicalEvent struct {
	ID          uuid.UUID       `json:"id"`
	OccurredAt  time.Time       `json:"occurred_at"`
	ActorKind   string          `json:"actor_kind"`
	ActorID     *uuid.UUID      `json:"actor_id,omitempty"`
	EventType   string          `json:"event_type"`
	SubjectKind string          `json:"subject_kind,omitempty"`
	SubjectID   *uuid.UUID      `json:"subject_id,omitempty"`
	Payload     json.RawMessage `json:"payload"`
	PrevHash    []byte          `json:"prev_hash"`
}

// canonicalize produces a stable byte representation. We use encoding/json's
// struct-tag-ordered output; Go's json encoder emits fields in struct order
// deterministically, and time.Time is UTC-normalized + µs-truncated so the
// post-DB-roundtrip value hashes identically.
func canonicalize(e canonicalEvent) []byte {
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	b, err := json.Marshal(e)
	if err != nil {
		// Panic acceptable: canonicalize feeds signing; if it fails the process is unsafe.
		panic(fmt.Errorf("audit: canonicalize: %w", err))
	}
	return b
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// canonicalPayload maps semantically equal JSON to identical bytes: decode
// into interface values, re-encode with encoding/json (map keys sorted,
// fixed spacing and number formatting). Needed because payload is stored as
// JSONB — Postgres rewrites key order, whitespace, and number text (e.g.
// 1e3 becomes 1000), so insert-time bytes and read-back bytes differ on
// honest ledgers. Both appendTx and Verify hash this canonical form.
//
// Numbers deliberately pass through float64 on both sides; that shared
// normalization is what makes the two sides agree. Do not switch this to
// json.Decoder.UseNumber — preserving the original number text on one side
// only would reintroduce the mismatch jsonb creates on the other.
func canonicalPayload(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("null"), nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("re-encode: %w", err)
	}
	return b, nil
}
