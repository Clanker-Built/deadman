package webui

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/gcottrell/deadman/control/internal/audit"
	"github.com/gcottrell/deadman/control/internal/store"
)

// buildUserExport assembles a JSON document containing every metadata
// record tied to userID. It deliberately does NOT include:
//
//   - Bundle ciphertext bytes (the operator can't read them anyway)
//   - WebAuthn credential private material (it never existed server-side)
//   - Session tokens (only their SHA-256 hashes ever lived in the DB)
//   - The release private key in any form
//
// It DOES include destination configurations as-is. Treat the export as
// sensitive — webhook URLs and email recipient addresses are PII for
// recipients, and could re-identify a third party.
func buildUserExport(ctx context.Context, s *store.Store, userID uuid.UUID) ([]byte, error) {
	out := map[string]any{
		"export_format_version": 1,
	}

	u, err := store.GetUserByID(ctx, s.Pool, userID)
	if err != nil {
		return nil, err
	}
	out["user"] = map[string]any{
		"id":           u.ID,
		"email":        u.Email,
		"display_name": u.DisplayName,
		"status":       u.Status,
		"is_admin":     u.IsAdmin,
		"created_at":   u.CreatedAt,
		"updated_at":   u.UpdatedAt,
	}

	creds, err := store.ListUserCredentials(ctx, s.Pool, userID)
	if err == nil {
		ws := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			ws = append(ws, map[string]any{
				"credential_id_hex": hex.EncodeToString(c.ID),
				"sign_count":        c.SignCount,
				"transports":        c.Transports,
				"aaguid_hex":        hex.EncodeToString(c.AAGUID),
				"label":             c.Label,
				"backup_eligible":   c.BackupEligible,
				"backup_state":      c.BackupState,
				"created_at":        c.CreatedAt,
			})
		}
		out["webauthn_credentials"] = ws
	}

	policies, _ := store.ListUserPolicies(ctx, s.Pool, userID)
	out["policies"] = policies
	out["policy_states"] = policyStatesFor(ctx, s, policies)

	bundles, _ := store.ListUserBundles(ctx, s.Pool, userID)
	bs := make([]map[string]any, 0, len(bundles))
	for _, b := range bundles {
		bs = append(bs, map[string]any{
			"id":                    b.ID,
			"label":                 b.Label,
			"version":               b.Version,
			"wrap_scheme":           b.WrapScheme,
			"primary_uri":           b.PrimaryURI,
			"backup_uri":            b.BackupURI,
			"size_bytes":            b.SizeBytes,
			"ciphertext_sha256_hex": hex.EncodeToString(b.CiphertextSHA256),
			"manifest_hash_hex":     hex.EncodeToString(b.ManifestHash),
			"created_at":            b.CreatedAt,
			"deleted_at":            b.DeletedAt,
		})
	}
	out["content_bundles_metadata"] = bs

	dests, _ := store.ListUserDestinations(ctx, s.Pool, userID)
	out["destinations"] = dests

	events, _ := audit.ListForUser(ctx, s.Pool, userID, 1000)
	out["audit_events"] = events

	return json.MarshalIndent(out, "", "  ")
}

func policyStatesFor(ctx context.Context, s *store.Store, ps []store.Policy) []*store.PolicyState {
	out := make([]*store.PolicyState, 0, len(ps))
	for _, p := range ps {
		st, err := store.GetPolicyState(ctx, s.Pool, p.ID)
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	return out
}
