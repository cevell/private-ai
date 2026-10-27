package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/system"
)

// KeyEnrollmentRequest represents the request body for dynamic public key registration.
type KeyEnrollmentRequest struct {
	PublicKey    string `json:"public_key"`
	PoPSignature string `json:"pop_signature,omitempty"`
	PoPTimestamp int64  `json:"pop_timestamp,omitempty"`
	PoPNonce     string `json:"pop_nonce,omitempty"`
}

// KeyEnrollmentResponse represents the response body upon successful key registration.
type KeyEnrollmentResponse struct {
	Status     string `json:"status"`
	PublicKey  string `json:"public_key"`
	EnrolledAt int64  `json:"enrolled_at"`
	Message    string `json:"message"`
}

// RegisterEnrollmentEndpoints wires the dynamic single-key enrollment endpoints:
// POST /v1/auth/register and POST /v1/auth/enroll.
func RegisterEnrollmentEndpoints(mux *http.ServeMux, verifier *auth.Ed25519Verifier, cfg *ServerConfig) {
	enrollHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		if verifier == nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Authentication verifier is not initialized",
			})
			return
		}

		if verifier.IsEnrolled() {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "A public key has already been registered on this CVM. Dynamic key enrollment is strictly single-key per lifecycle.",
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to read request body: " + err.Error(),
			})
			return
		}

		var req KeyEnrollmentRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid JSON payload: " + err.Error(),
			})
			return
		}

		pubKey, hexStr, err := auth.ParsePublicKeyHex(req.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Invalid public_key: %v", err),
			})
			return
		}

		// Support embedded body PoP signature if Authorization header is omitted
		if r.Header.Get("Authorization") == "" && req.PoPSignature != "" {
			reqID := r.Header.Get("X-Cevell-Request-ID")
			if reqID == "" {
				reqID = r.Header.Get("X-Arvex-Request-ID")
			}
			if reqID == "" {
				reqID = "pop-enroll"
			}
			r.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s",
				req.PoPSignature, req.PoPTimestamp, req.PoPNonce, reqID))
		}

		if err := verifier.VerifyProofOfPossession(pubKey, r, bodyBytes); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Proof-of-possession verification failed: %v", err),
			})
			return
		}

		if err := verifier.EnrollKey(pubKey); err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		if cfg != nil && cfg.AttestationDoc != nil {
			cfg.AttestationDoc.Predicate.AuthorizedPublicKey = hexStr
		}

		system.Log("[AUTH] Authorized Ed25519 public key successfully enrolled: %s", hexStr)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(KeyEnrollmentResponse{
			Status:     "enrolled",
			PublicKey:  hexStr,
			EnrolledAt: time.Now().Unix(),
			Message:    "Authorized public key successfully enrolled. System is now locked to this tenant identity.",
		})
	}

	mux.HandleFunc("/v1/auth/register", enrollHandler)
	mux.HandleFunc("/v1/auth/enroll", enrollHandler)
}
