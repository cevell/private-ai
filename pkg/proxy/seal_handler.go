package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/network"
	"github.com/cevell/private-ai/pkg/system"
)

// sealState tracks whether the enclave has been hermetically sealed.
// Uses atomic.Int32 for lock-free, zero-allocation reads from the HTTP hot path.
var sealState atomic.Int32 // 0 = open, 1 = sealed

// IsSealed returns true if the enclave has been sealed.
func IsSealed() bool {
	return sealState.Load() != 0
}

// SetSealedForTesting allows unit tests to configure seal state.
func SetSealedForTesting(val bool) {
	if val {
		sealState.Store(1)
	} else {
		sealState.Store(0)
	}
}

// ModelSupervisor abstracts the status methods needed from the inference supervisor.
type ModelSupervisor interface {
	IsReady() bool
	CurrentModel() string
}

// SealConfig holds dependencies for the seal endpoint.
type SealConfig struct {
	Verifier      *auth.Ed25519Verifier
	Supervisor    ModelSupervisor
	EgressApplier func() error // Defaults to network.ApplySealedEgressPolicy; injectable for testing
}

// SealAuthGuard wraps an HTTP handler to require valid Ed25519 authentication
// when the enclave is in the sealed state. When unsealed, the request passes
// through unconditionally to preserve pre-attestation public discovery.
func SealAuthGuard(verifier *auth.Ed25519Verifier, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsSealed() {
			if verifier == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication verifier is not initialized",
				})
				return
			}

			bodyBytes, err := verifier.VerifyHTTPRequestHeaderFirst(w, r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Enclave is sealed: authentication required: %v", err),
				})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		next(w, r)
	}
}

// RegisterSealEndpoint registers POST /v1/system/seal on the provided mux.
// This endpoint enforces Ed25519 authentication, verifies that a model is loaded and ready,
// triggers kernel-level egress lockdown, and permanently latches the sealed state.
func RegisterSealEndpoint(mux *http.ServeMux, cfg *SealConfig) {
	mux.HandleFunc("/v1/system/seal", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Idempotency: if already sealed, return success without re-executing
		if IsSealed() {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":          "already_sealed",
				"sealed":          true,
				"outbound_egress": "blocked",
				"inbound_policy":  "authenticated_only",
			})
			return
		}

		// Authenticate with Ed25519
		if cfg == nil || cfg.Verifier == nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Authentication verifier is not initialized",
			})
			return
		}

		bodyBytes, err := cfg.Verifier.VerifyHTTPRequestHeaderFirst(w, r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Authentication failed: %v", err),
			})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Parse optional SealRequest payload for "force" flag
		var sealReq struct {
			Force bool `json:"force"`
		}
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &sealReq)
		}

		// Precondition: Model must be loaded and inference engine ready (unless force=true)
		if !sealReq.Force {
			if cfg.Supervisor == nil || !cfg.Supervisor.IsReady() {
				w.WriteHeader(http.StatusPreconditionFailed)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Cannot seal: no model is loaded or inference engine is not ready. Load a model and verify working inference before sealing (or provide force: true).",
				})
				return
			}
		}

		// Execute egress firewall lockdown
		egressFn := cfg.EgressApplier
		if egressFn == nil {
			egressFn = network.ApplySealedEgressPolicy
		}
		if err := egressFn(); err != nil {
			system.LogError("[SEAL FAILED] Could not apply sealed egress policy: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Seal failed: egress policy application error: %v", err),
			})
			return
		}

		// Latch sealed state permanently
		sealState.Store(1)
		sealedAt := time.Now().Unix()
		system.Log("[SEAL] Enclave hermetically sealed at %d (forced=%v). All outbound egress blocked. All inbound requests require authentication.", sealedAt, sealReq.Force)

		activeModel := ""
		if cfg.Supervisor != nil {
			activeModel = cfg.Supervisor.CurrentModel()
		}

		resp := map[string]any{
			"status":          "sealed",
			"sealed":          true,
			"sealed_at":       sealedAt,
			"outbound_egress": "blocked",
			"inbound_policy":  "authenticated_only",
			"active_model":    activeModel,
		}
		if sealReq.Force {
			resp["forced"] = true
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// RegisterEgressProbeEndpoint registers POST /v1/system/probe-egress on the provided mux.
// It integrates with VisibilityManager to support dynamic visibility toggles (defaulting to hidden).
// When hidden or sealed, it requires client Ed25519 authentication.
// When toggled to public (and unsealed), it permits unauthenticated connectivity checks.
// In unenrolled state, it returns 401 Unauthorized.
func RegisterEgressProbeEndpoint(mux *http.ServeMux, verifier *auth.Ed25519Verifier, vm ...*VisibilityManager) {
	var visibilityMgr *VisibilityManager
	if len(vm) > 0 && vm[0] != nil {
		visibilityMgr = vm[0]
	} else {
		visibilityMgr = NewVisibilityManager(verifier)
	}

	probeHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		target := "1.1.1.1:443"
		timeoutSec := 3
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Failed to read request body",
				})
				return
			}
			if len(bodyBytes) > 0 {
				var probeReq struct {
					Target     string `json:"target"`
					TimeoutSec int    `json:"timeout_sec"`
				}
				if err := json.Unmarshal(bodyBytes, &probeReq); err == nil {
					if probeReq.Target != "" {
						target = probeReq.Target
					}
					if probeReq.TimeoutSec > 0 && probeReq.TimeoutSec <= 10 {
						timeoutSec = probeReq.TimeoutSec
					}
				}
			}
		}

		start := time.Now()
		conn, dialErr := net.DialTimeout("tcp", target, time.Duration(timeoutSec)*time.Second)
		latency := time.Since(start).Milliseconds()

		if dialErr != nil {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"egress_probe":        "blocked",
				"internet_accessible": false,
				"target":              target,
				"error":               dialErr.Error(),
				"latency_ms":          latency,
				"sealed":              IsSealed(),
			})
			return
		}
		_ = conn.Close()

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"egress_probe":        "success",
			"internet_accessible": true,
			"target":              target,
			"latency_ms":          latency,
			"sealed":              IsSealed(),
		})
	}

	mux.HandleFunc("/v1/system/probe-egress", visibilityMgr.GuardNonCritical("probe_egress", probeHandler))
}

