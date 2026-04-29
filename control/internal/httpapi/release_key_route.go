package httpapi

import (
	"crypto/rsa"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/gcottrell/deadman/control/internal/crypto"
)

// mountReleaseKeyRoute exposes the server's release public key so browsers
// can encrypt bundle DEKs against it via WebCrypto RSA-OAEP.
func mountReleaseKeyRoute(r chi.Router, pub *rsa.PublicKey) {
	r.Get("/release/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"scheme": crypto.SchemeRSAOAEPAESGCM,
			"jwk":    crypto.ReleasePublicKeyJWK(pub),
		})
	})
}
